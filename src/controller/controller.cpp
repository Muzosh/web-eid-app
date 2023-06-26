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

#include "controller.hpp"

#include "threads/eidcontainereventmonitorthread.hpp"
#include "threads/commandhandlerconfirmthread.hpp"
#include "threads/commandhandlerrunthread.hpp"
#include "threads/waitforeidcontainerthread.hpp"

#include "utils/utils.hpp"
#include "inputoutputmode.hpp"
#include "writeresponse.hpp"

#include <QApplication>

using namespace pcsc_cpp;
using namespace electronic_id;

namespace
{

// TODO: Should we use more detailed error codes? E.g. report input data error back to the website
// etc.
const QString RESP_TECH_ERROR = QStringLiteral("ERR_WEBEID_NATIVE_FATAL");
const QString RESP_USER_CANCEL = QStringLiteral("ERR_WEBEID_USER_CANCELLED");

QVariantMap makeErrorObject(const QString& errorCode, const QString& errorMessage)
{
    const auto errorBody = QVariantMap {
        {QStringLiteral("code"), errorCode},
        {QStringLiteral("message"), errorMessage},
    };
    return {{QStringLiteral("error"), errorBody}};
}

void interruptThread(QThread* thread)
{
    qDebug() << "Interrupting thread" << uintptr_t(thread);
    thread->disconnect();
    thread->requestInterruption();
    ControllerChildThread::waitForControllerNotify.wakeAll();
}

} // namespace

void Controller::run()
{
    // If a command is passed, the application is in command-line mode, else in stdin/stdout mode.
    const bool isInCommandLineMode = bool(command);
    isInStdinMode = !isInCommandLineMode;

    qInfo() << qApp->applicationName() << "app" << qApp->applicationVersion() << "running in"
            << (isInStdinMode ? "stdin/stdout" : "command-line") << "mode";

    try {
        // TODO: cut out stdin mode separate class to avoid bugs in safari mode
        if (isInStdinMode) {
            // In stdin/stdout mode we first output the version as required by the WebExtension
            // and then wait for the actual command.
            writeResponseToStdOut(isInStdinMode,
                                  {{QStringLiteral("version"), qApp->applicationVersion()}},
                                  "get-version");

            command = readCommandFromStdin();
        }

        REQUIRE_NON_NULL(command)
        switch (command->first) {
        case CommandType::ABOUT:
            WebEidUI::showAboutPage();
            return;
        case CommandType::QUIT:
            // If quit is requested, respond with empty JSON object and quit immediately.
            qInfo() << "Quit requested, exiting";
            writeResponseToStdOut(true, {}, "quit");
            emit quit();
            return;
        default:
            break;
        }

        commandHandler = getCommandHandler(*command);

        startCommandExecution();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void Controller::startCommandExecution()
{
    REQUIRE_NON_NULL(commandHandler)

    // Reader monitor thread setup.
    WaitForEidContainerThread* waitForEidContainerThread = new WaitForEidContainerThread(this);
    connect(waitForEidContainerThread, &WaitForEidContainerThread::statusUpdate, this,
            &Controller::statusUpdate);
    connect(waitForEidContainerThread, &WaitForEidContainerThread::eidContainersAvailable, this,
            &Controller::onEidContainersAvailable);
    saveChildThreadPtrAndConnectFailureFinish(waitForEidContainerThread);

    // UI setup.
    window = WebEidUI::createAndShowDialog(commandHandler->commandType());
    connect(this, &Controller::statusUpdate, window, &WebEidUI::onEidContainerStatusUpdate);
    connectOkCancelWaitingForPinPad();

    // Finally, start the thread to wait for eid container insertion after everything is wired up.
    waitForEidContainerThread->start();
}

void Controller::saveChildThreadPtrAndConnectFailureFinish(ControllerChildThread* childThread)
{
    REQUIRE_NON_NULL(childThread)
    // Save the thread pointer in child thread tracking map to request interruption and wait for
    // it to quit in waitForChildThreads().
    childThreads[uintptr_t(childThread)] = childThread;

    connect(childThread, &ControllerChildThread::failure, this, &Controller::onCriticalFailure);

    // When the thread is finished, remove the pointer from the tracking map and call deleteLater()
    // on it to free the thread object. Although the thread objects are freed through the Qt object
    // tree ownership system anyway, it is better to delete them immediately when they finish.
    connect(childThread, &ControllerChildThread::finished, this, [this, childThread]() {
        QScopedPointer<ControllerChildThread, QScopedPointerDeleteLater> deleteLater {childThread};

        const auto threadPtrAddress = uintptr_t(childThread);
        if (childThreads.count(threadPtrAddress) && childThreads[threadPtrAddress]) {
            childThreads[threadPtrAddress] = nullptr;
            childThread->wait();
            qDebug() << "Thread" << threadPtrAddress << "finished";
        } else {
            qWarning() << "Controller child thread" << childThread
                       << "is missing or null in finish slot";
        }
    });
}

void Controller::connectOkCancelWaitingForPinPad()
{
    REQUIRE_NON_NULL(window)

    connect(window, &WebEidUI::accepted, this, &Controller::onDialogOK);
    connect(window, &WebEidUI::rejected, this, &Controller::onDialogCancel);
    connect(window, &WebEidUI::failure, this, &Controller::onCriticalFailure);
    connect(window, &WebEidUI::waitingForPinPad, this, &Controller::onConfirmCommandHandler);
}

void Controller::onEidContainersAvailable(
    const std::vector<electronic_id::EidContainerInfo::ptr>& eidContainers)
{
    try {
        REQUIRE_NON_NULL(commandHandler)
        REQUIRE_NON_NULL(window)
        REQUIRE_NOT_EMPTY_CONTAINS_NON_NULL_PTRS(eidContainers)

        for (const auto& eidContainerInfo : eidContainers) {
            if (eidContainerInfo->containerType() == EidContainerInfo::ContainerType::CardInfo) {
                const CardInfo::ptr cardInfo =
                    std::dynamic_pointer_cast<CardInfo>(eidContainerInfo);

                const auto protocol =
                    cardInfo->eid().smartcard().protocol() == SmartCard::Protocol::T0 ? "T=0"
                                                                                      : "T=1";
                qInfo() << "Card" << cardInfo->eid().name() << "in reader"
                        << cardInfo->reader().name << "using protocol" << protocol;
            } else if (eidContainerInfo->containerType()
                       == EidContainerInfo::ContainerType::SerialDeviceInfo) {
                const SerialDeviceInfo::ptr serialDeviceInfo =
                    std::dynamic_pointer_cast<SerialDeviceInfo>(eidContainerInfo);

                qInfo() << "Serial device " << serialDeviceInfo->eid().name() << "in port "
                        << serialDeviceInfo->serialPort().qPortInfo.systemLocation().toStdString();
            }
        }

        window->showWaitingForEidContainerPage(commandHandler->commandType());

        commandHandler->connectSignals(window);

        runCommandHandler(eidContainers);

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void Controller::runCommandHandler(
    const std::vector<electronic_id::EidContainerInfo::ptr>& availableEidContainers)
{
    try {
        CommandHandlerRunThread* commandHandlerRunThread =
            new CommandHandlerRunThread(this, *commandHandler, availableEidContainers);
        saveChildThreadPtrAndConnectFailureFinish(commandHandlerRunThread);
        connectRetry(commandHandlerRunThread);

        // When the command handler run thread retrieves certificates successfully, call
        // onCertificatesLoaded() that starts eid container event monitoring while user enters the
        // PIN.
        connect(commandHandler.get(), &CommandHandler::singleCertificateReady, this,
                &Controller::onCertificatesLoaded);
        connect(commandHandler.get(), &CommandHandler::multipleCertificatesReady, this,
                &Controller::onCertificatesLoaded);

        commandHandlerRunThread->start();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void Controller::onCertificatesLoaded()
{
    EidContainerEventMonitorThread* eidContainerEventMonitorThread =
        new EidContainerEventMonitorThread(this, std::string(commandType()));
    saveChildThreadPtrAndConnectFailureFinish(eidContainerEventMonitorThread);
    eidContainerEventMonitorThreadKey = uintptr_t(eidContainerEventMonitorThread);
    connect(eidContainerEventMonitorThread, &EidContainerEventMonitorThread::eidContainerEvent,
            this, &Controller::onRetry);
    eidContainerEventMonitorThread->start();
}

void Controller::stopEidContainerEventMonitorThread()
{
    if (eidContainerEventMonitorThreadKey) {
        try {
            auto eidContainerEventMonitorThread =
                childThreads.at(eidContainerEventMonitorThreadKey);
            eidContainerEventMonitorThreadKey = 0;
            if (eidContainerEventMonitorThread) {
                interruptThread(eidContainerEventMonitorThread);
            }
        } catch (const std::out_of_range&) {
            qWarning()
                << "EidContainer event monitor thread" << eidContainerEventMonitorThreadKey
                << "is missing from childThreads map in stopEidContainerEventMonitorThread()";
            eidContainerEventMonitorThreadKey = 0;
        }
    }
}

void Controller::disposeUI()
{
    if (window) {
        window->disconnect();
        // As the Qt::WA_DeleteOnClose flag is set, the dialog is deleted automatically.
        window->close();
        window = nullptr;
    }
}

void Controller::onConfirmCommandHandler(
    const EidContainerCertificateAndPinInfo& eidContainerCertAndPinInfo)
{
    stopEidContainerEventMonitorThread();

    try {
        CommandHandlerConfirmThread* commandHandlerConfirmThread = new CommandHandlerConfirmThread(
            this, *commandHandler, window, eidContainerCertAndPinInfo);
        connect(commandHandlerConfirmThread, &CommandHandlerConfirmThread::completed, this,
                &Controller::onCommandHandlerConfirmCompleted);
        saveChildThreadPtrAndConnectFailureFinish(commandHandlerConfirmThread);
        connectRetry(commandHandlerConfirmThread);

        commandHandlerConfirmThread->start();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void Controller::onCommandHandlerConfirmCompleted(const QVariantMap& res)
{
    REQUIRE_NON_NULL(window)

    qDebug() << "Command completed";

    // Schedule application exit when the UI dialog is destroyed.
    connect(window, &WebEidUI::destroyed, this, &Controller::exit);

    try {
        _result = res;
        writeResponseToStdOut(isInStdinMode, res, commandHandler->commandType());
    } catch (const std::exception& error) {
        qCritical() << "Command" << std::string(commandType())
                    << "fatal error while writing response to stdout:" << error;
    }

    window->quit();
}

void Controller::onRetry()
{
    try {
        // Dispose the UI, it will be re-created during next execution.
        disposeUI();
        // Command handler signals are still connected, disconnect them so that they can be
        // reconnected during next execution.
        commandHandler->disconnect();
        // Before restarting, wait until child threads finish.
        waitForChildThreads();

        startCommandExecution();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void Controller::connectRetry(const ControllerChildThread* childThread)
{
    REQUIRE_NON_NULL(childThread)
    REQUIRE_NON_NULL(window)

    disconnect(window, &WebEidUI::retry, nullptr, nullptr);

    connect(childThread, &ControllerChildThread::retry, window, &WebEidUI::onRetry);
    // This connection handles cancel events from PIN pad.
    connect(childThread, &ControllerChildThread::cancel, this, &Controller::onPinPadCancel);
    connect(window, &WebEidUI::retry, this, &Controller::onRetry);
}

void Controller::onDialogOK(const EidContainerCertificateAndPinInfo& eidContainerCertAndPinInfo)
{
    if (commandHandler) {
        onConfirmCommandHandler(eidContainerCertAndPinInfo);
    } else {
        // This should not happen, and when it does, OK should be equivalent to cancel.
        onPinPadCancel();
    }
}

void Controller::onDialogCancel()
{
    REQUIRE_NON_NULL(window)

    qDebug() << "User cancelled";

    // Schedule application exit when the UI dialog is destroyed.
    connect(window, &WebEidUI::destroyed, this, &Controller::exit);

    _result = makeErrorObject(RESP_USER_CANCEL, QStringLiteral("User cancelled"));
    writeResponseToStdOut(isInStdinMode, _result, commandType());
}

void Controller::onPinPadCancel()
{
    REQUIRE_NON_NULL(window)

    onDialogCancel();
    window->quit();
}

void Controller::onCriticalFailure(const QString& error)
{
    qCritical() << "Exiting due to command" << std::string(commandType())
                << "fatal error:" << error;
    _result = makeErrorObject(RESP_TECH_ERROR, error);
    writeResponseToStdOut(isInStdinMode, _result, commandType());
    disposeUI();
    WebEidUI::showFatalError();
    exit();
}

void Controller::exit()
{
    if (window) {
        window->disconnect();
        window = nullptr;
    }
    waitForChildThreads();
    emit quit();
}

void Controller::waitForChildThreads()
{
    // Waiting for child threads must not happen in destructor.
    // See https://tombarta.wordpress.com/2008/07/10/gcc-pure-virtual-method-called/ for details.
    for (const auto& childThread : childThreads) {
        auto thread = childThread.second;
        if (thread) {
            interruptThread(thread);
            // Waiting for PIN input on PIN pad may take a long time, call processEvents() so that
            // the UI doesn't freeze.
            while (thread->isRunning()) {
                thread->wait(100); // in milliseconds
                QCoreApplication::processEvents();
            }
        }
    }
}

CommandType Controller::commandType()
{
    return commandHandler ? commandHandler->commandType()
                          : CommandType(CommandType::INSERT_EID_CONTAINER);
}
