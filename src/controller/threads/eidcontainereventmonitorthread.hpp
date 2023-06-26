/*
 * Copyright (c) 2021-2022 Estonian Information System Authority
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
#include "electronic-id/electronic-id.hpp"

class EidContainerEventMonitorThread : public ControllerChildThread
{
    Q_OBJECT

public:
    using std_string_set = std::set<std::string>;

    EidContainerEventMonitorThread(QObject* parent, const std::string& commandType) :
        ControllerChildThread(parent), cmdType(commandType)
    {
    }

    void run() override
    {
        QMutexLocker lock {&controllerChildThreadMutex};

        beforeRun();

        std_string_set initialEidContainerNames = getInitialEidContainerNames();

        while (!isInterruptionRequested()) {

            waitForControllerNotify.wait(&controllerChildThreadMutex, ONE_SECOND);

            std_string_set updatedEidContainers {};

            try {
                // Get available eid containers
                std::vector<electronic_id::EidContainerInfo::ptr> eidInfos =
                    electronic_id::availableSupportedEidContainers();

                // Extract just the names of the eid containers
                std::transform(eidInfos.begin(), eidInfos.end(),
                               std::inserter(updatedEidContainers, updatedEidContainers.end()),
                               [](const electronic_id::EidContainerInfo::ptr& eidInfo) {
                                   return eidInfo->eidContainerInfoName();
                               });
            } catch (const std::exception& error) {
                // Ignore eid container layer errors, they will be handled during next eid container
                // operation.
                qWarning() << className << "ignoring" << commandType() << "error:" << error;
            }

            // If interruption was requested during wait, exit without emitting.
            if (isInterruptionRequested()) {
                return;
            }

            // If there was a change in connected supported eid containers, exit after emitting a
            // eid container event.
            if (!areEqualByName(initialEidContainerNames, updatedEidContainers)) {
                qDebug() << className << "eid container change detected";
                emit eidContainerEvent();
                return;
            }
        }
    }

signals:
    void eidContainerEvent();

private:
    void doRun() override
    {
        // Unused as run() has been overriden.
    }

    std_string_set getInitialEidContainerNames()
    {
        while (!isInterruptionRequested()) {
            try {
                std_string_set eidContainerInfoNames;

                // Get available eid containers.
                std::vector<electronic_id::EidContainerInfo::ptr> eidInfos =
                    electronic_id::availableSupportedEidContainers();

                // Extract just the names of the eid containers
                std::transform(eidInfos.begin(), eidInfos.end(),
                               std::inserter(eidContainerInfoNames, eidContainerInfoNames.end()),
                               [](const electronic_id::EidContainerInfo::ptr& eidInfo) {
                                   return eidInfo->eidContainerInfoName();
                               });

                return eidContainerInfoNames;
            } catch (const std::exception& error) {
                // Ignore eid containers layer errors, they will be handled during next eid
                // container operation.
                qWarning() << className << "ignoring" << commandType() << "error:" << error;
            }
            waitForControllerNotify.wait(&controllerChildThreadMutex, ONE_SECOND);
        }
        // Interruption was requested, return empty list.
        return {};
    }

    bool areEqualByName(const std_string_set& a, const std_string_set& b)
    {
        // std::equal requires that second range is not shorter than first, so compare size first.
        return a.size() == b.size() && a == b;
    }

    const std::string& commandType() const override { return cmdType; }

    const std::string cmdType;
};
