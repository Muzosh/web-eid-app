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

#pragma once

#include "commands.hpp"
#include "certandpininfo.hpp"
#include "retriableerror.hpp"

#include "utils/observer_ptr.hpp"

#include <QDialog>

/**
 * The UI interface implemented in the ui and mock-ui projects.
 */
class WebEidUI : public QDialog
{
    Q_OBJECT

public:
    explicit WebEidUI(QWidget* parent = nullptr) : QDialog(parent) {}

    // Factory function that creates and shows the dialog that implements this interface.
    static observer_ptr<WebEidUI> createAndShowDialog(const CommandType command);

    static void showAboutPage();
    static void showFatalError();

    virtual void showWaitingForCardPage(const CommandType commandType) = 0;

    // getPin() is called from background threads and must be thread-safe.
    virtual QString getPin() = 0;

signals:
    void waitingForPinPad(const CardCertificateAndPinInfo& cardCertAndPinInfo);
    void accepted(const CardCertificateAndPinInfo& cardCertAndPinInfo);
    void retry();
    void failure(const QString& error);

public: // slots
    virtual void quit() = 0;
    virtual void onSmartCardStatusUpdate(const RetriableError status) = 0;
    virtual void onMultipleCertificatesReady(
        const QUrl& origin, const std::vector<CardCertificateAndPinInfo>& cardCertAndPinInfos) = 0;
    virtual void onSingleCertificateReady(const QUrl& origin,
                                          const CardCertificateAndPinInfo& cardCertAndPinInfo) = 0;

    virtual void onRetry(const RetriableError error) = 0;

    virtual void onSigningCertificateMismatch() = 0;
    virtual void onVerifyPinFailed(const electronic_id::VerifyPinFailed::Status status,
                                   const qint8 retriesLeft) = 0;
};
