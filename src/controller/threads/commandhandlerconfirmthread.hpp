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

#include "controllerchildthread.hpp"

class CommandHandlerConfirmThread : public ControllerChildThread
{
    Q_OBJECT

public:
    CommandHandlerConfirmThread(QObject* parent, CommandHandler& handler, WebEidUI* w,
                                const CardCertificateAndPinInfo& cardCertAndPin) :
        ControllerChildThread(parent),
        commandHandler(handler), cmdType(commandHandler.commandType()), window(w),
        cardCertAndPinInfo(cardCertAndPin)
    {
    }

signals:
    void completed(const QVariantMap& result);

private:
    void doRun() override
    {
        const auto result = commandHandler.onConfirm(window, cardCertAndPinInfo);
        emit completed(result);
    }

    const std::string& commandType() const override { return cmdType; }

    CommandHandler& commandHandler;
    const std::string cmdType;
    WebEidUI* window;
    CardCertificateAndPinInfo cardCertAndPinInfo;
};
