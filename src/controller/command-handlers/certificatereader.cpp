/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "certificatereader.hpp"

#include "application.hpp"
#include "signauthutils.hpp"
#include "utils/utils.hpp"
#include "magic_enum/magic_enum.hpp"

using namespace electronic_id;

namespace
{

EidContainerCertificateAndPinInfo
getCertificateWithStatusAndInfo(const EidContainerInfo::ptr& eidContainerInfo,
                                const CertificateType certificateType)
{
    const auto certificateBytes = eidContainerInfo->eid().getCertificate(certificateType);

    auto certificateDer = QByteArray(reinterpret_cast<const char*>(certificateBytes.data()),
                                     int(certificateBytes.size()));
    auto certificate = QSslCertificate(certificateDer, QSsl::Der);
    if (certificate.isNull()) {
        THROW(SmartCardChangeRequiredError,
              "Invalid certificate returned by electronic ID " + eidContainerInfo->eid().name());
    }

    auto subject = certificate.subjectInfo(QSslCertificate::CommonName).join(' ');
    auto givenName = certificate.subjectInfo("GN").join(' ');
    auto surName = certificate.subjectInfo("SN").join(' ');
    auto serialNumber = certificate.subjectInfo(QSslCertificate::SerialNumber).join(' ');

    // http://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.01_60/en_31941201v010101p.pdf
    if (serialNumber.size() > 6 && serialNumber.startsWith(QStringLiteral("PNO"))
        && serialNumber[5] == '-')
        serialNumber.remove(0, 6);

    if (!givenName.isEmpty() && !surName.isEmpty() && !serialNumber.isEmpty()) {
        subject = QStringLiteral("%1, %2, %3").arg(surName, givenName, serialNumber);
    }

    auto certInfo = CertificateInfo {certificateType,
                                     certificate.expiryDate() < QDateTime::currentDateTimeUtc(),
                                     certificate.effectiveDate() > QDateTime::currentDateTimeUtc(),
                                     subject,
                                     certificate.issuerInfo(QSslCertificate::CommonName).join(' '),
                                     certificate.effectiveDate().date().toString(Qt::ISODate),
                                     certificate.expiryDate().date().toString(Qt::ISODate)};
    electronic_id::EidContainerInfo::ContainerType containerType =
        eidContainerInfo->containerType();

    auto pinInfo = PinInfo {
        certificateType.isAuthentication() ? eidContainerInfo->eid().authPinMinMaxLength()
                                           : eidContainerInfo->eid().signingPinMinMaxLength(),
        certificateType.isAuthentication() ? eidContainerInfo->eid().authPinRetriesLeft()
                                           : eidContainerInfo->eid().signingPinRetriesLeft(),
        (containerType == EidContainerInfo::ContainerType::CardInfo)
            ? std::dynamic_pointer_cast<CardInfo>(eidContainerInfo)
                  ->eid()
                  .smartcard()
                  .readerHasPinPad()
            : std::dynamic_pointer_cast<SerialDeviceInfo>(eidContainerInfo)
                  ->serialPort()
                  .hasPinPad};
    if (pinInfo.pinRetriesCount.first == 0) {
        pinInfo.pinIsBlocked = true;
    }

    return {eidContainerInfo, certificateDer, certificate, certInfo, pinInfo};
}

} // namespace

CertificateReader::CertificateReader(const CommandWithArguments& cmd) : CommandHandler(cmd)
{
    validateAndStoreOrigin(cmd.second);
    if (Application* app = qobject_cast<Application*>(qApp)) {
        app->loadTranslations(cmd.second.value(QStringLiteral("lang")).toString());
    }
}

void CertificateReader::run(const std::vector<EidContainerInfo::ptr>& eidContainers)
{
    REQUIRE_NOT_EMPTY_CONTAINS_NON_NULL_PTRS(eidContainers)

    certificateType = command.first == CommandType::AUTHENTICATE ? CertificateType::AUTHENTICATION
                                                                 : CertificateType::SIGNING;

    std::vector<EidContainerCertificateAndPinInfo> certInfos;
    certInfos.reserve(eidContainers.size());
    for (const auto& eidContainerInfo : eidContainers) {
        try {
            certInfos.push_back(getCertificateWithStatusAndInfo(eidContainerInfo, certificateType));
        } catch (const WrongCertificateTypeError&) {
            // Ignore eIDs that don't support the given ceritifcate type.
        }
    }

    if (certInfos.empty()) {
        emit retry(RetriableError::NO_VALID_CERTIFICATE_AVAILABLE);
    } else {
        emitCertificatesReady(certInfos);
    }
}

void CertificateReader::connectSignals(const WebEidUI* window)
{
    window->disconnect(this);
    connect(this, &CertificateReader::multipleCertificatesReady, window,
            &WebEidUI::onMultipleCertificatesReady);
    connect(this, &CertificateReader::singleCertificateReady, window,
            &WebEidUI::onSingleCertificateReady);
}

void CertificateReader::emitCertificatesReady(
    const std::vector<EidContainerCertificateAndPinInfo>& certInfos)
{
    if (certInfos.size() == 1) {
        emit singleCertificateReady(origin, certInfos[0]);
    } else {
        emit multipleCertificatesReady(origin, certInfos);
    }
}

void CertificateReader::validateAndStoreOrigin(const QVariantMap& arguments)
{
    const auto originStr = validateAndGetArgument<QString>(QStringLiteral("origin"), arguments);
    if (originStr.size() > 255) {
        THROW(CommandHandlerInputDataError, "origin length cannot exceed 255 characters");
    }

    origin = QUrl(originStr, QUrl::ParsingMode::StrictMode);

    if (!origin.isValid()) {
        THROW(CommandHandlerInputDataError, "origin is not a valid URL");
    }
    if (origin.isRelative() || !origin.path().isEmpty() || origin.hasQuery()
        || origin.hasFragment()) {
        THROW(CommandHandlerInputDataError, "origin is not in <scheme>://<host>[:<port>] format");
    }
    if (origin.scheme() != QStringLiteral("https") && origin.scheme() != QStringLiteral("wss")) {
        THROW(CommandHandlerInputDataError, "origin scheme has to be https or wss");
    }
}
