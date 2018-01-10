# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Progresser"""

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc
# pylint: disable=missing-param-doc

# TODO: probably should unify this with inventory/base/progress.py


class Progress(object):
    """Progress state."""

    def __init__(self, final_message=False, step="", entity_id=-1):
        self.entity_id = entity_id
        self.final_message = final_message
        self.step = step
        self.warnings = 0
        self.errors = 0
        self.last_warning = ""
        self.last_error = ""


class QueueProgresser(Progress):
    """Queue based progresser."""

    def __init__(self, queue):
        super(QueueProgresser, self).__init__()
        self.queue = queue

    def _notify(self):
        """Notify status update into queue."""

        self.queue.put_nowait(self)

    def _notify_eof(self):
        """Notify end of status updates into queue."""

        self.queue.put(None)

    def on_new_object(self, obj_desc):
        """Update the status with the new object."""

        self.step = obj_desc
        self._notify()

    def on_warning(self, warning):
        """Stores the warning and updates the counter."""

        self.last_warning = warning
        self.warnings += 1
        self._notify()

    def on_error(self, error):
        """Stores the error and updates the counter."""

        self.last_error = error
        self.errors += 1
        self._notify()

    def get_summary(self):
        """Indicate end of updates, and return self as last state.

        Returns:
            object: Progresser in its last state.
        """

        self.final_message = True
        self._notify()
        self._notify_eof()
        return self


class FirstMessageQueueProgresser(QueueProgresser):
    """Queue base progresser only delivers first message.
    Then throws away all subsequent messages. This is used
    to make sure that we're not creating an internal buffer of
    infinite size as we're crawling in background without a queue consumer."""

    def __init__(self, *args, **kwargs):
        super(FirstMessageQueueProgresser, self).__init__(*args, **kwargs)
        self.first_message_sent = False

    def _notify(self):
        if not self.first_message_sent:
            self.first_message_sent = True
            QueueProgresser._notify(self)

    def _notify_eof(self):
        if not self.first_message_sent:
            self.first_message_sent = True
        QueueProgresser._notify_eof(self)
