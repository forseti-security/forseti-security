# Copyright 2017 Google Inc.
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

"""Logging API Client.

Some of the code has been lifted from:

https://github.com/GoogleCloudPlatform/google-cloud-python/blob/master/logging/google/cloud/logging
"""

import logging

from google.cloud.security.common.gcp_api._base_client import _BaseClient
from google.cloud.security.common.third_party.transports.background_thread import BackgroundThreadTransport


_RFC3339_MICROS = '%Y-%m-%dT%H:%M:%S.%fZ'


def _datetime_to_rfc3339(value, ignore_zone=True):
    """Convert a timestamp to a string.

    :type value: :class:`datetime.datetime`
    :param value: The datetime object to be converted to a string.

    :type ignore_zone: bool
    :param ignore_zone: If True, then the timezone (if any) of the datetime
                        object is ignored.

    :rtype: str
    :returns: The string representing the datetime stamp.
    """
    if not ignore_zone and value.tzinfo is not None:
        # Convert to UTC and remove the time zone info.
        value = value.replace(tzinfo=None) - value.utcoffset()

    return value.strftime(_RFC3339_MICROS)


class LoggingClient(_BaseClient):
    """Logging Client."""

    API_NAME = 'logging'

    def __init__(self, credentials=None):
        super(LoggingClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)

    def get_logger(self):
        return CloudLogger(__name__, self)

    def write_entries(self, entries, logger_name=None, resource=None,
                      labels=None):
        """API call:  log an entry resource via a POST request

        See:
        https://cloud.google.com/logging/docs/api/reference/rest/v2/entries/write

        :type entries: sequence of mapping
        :param entries: the log entry resources to log.

        :type logger_name: str
        :param logger_name: name of default logger to which to log the entries;
                            individual entries may override.

        :type resource: mapping
        :param resource: default resource to associate with entries;
                         individual entries may override.

        :type labels: mapping
        :param labels: default labels to associate with entries;
                       individual entries may override.
        """
        data = {'entries': list(entries)}

        if logger_name is not None:
            data['logName'] = logger_name

        if resource is not None:
            data['resource'] = resource

        if labels is not None:
            data['labels'] = labels

        self.service.entries().write(body=data).execute()


class CloudLoggingHandler(logging.StreamHandler):
    """Cloud Logging Handler.

    See: https://github.com/GoogleCloudPlatform/google-cloud-python/blob/master/logging/google/cloud/logging/handlers/handlers.py
    """

    LOGGER_NAME = 'cloud_logger'

    def __init__(self,
                 client,
                 name=LOGGER_NAME,
                 transport=BackgroundThreadTransport):
        super(CloudLoggingHandler, self).__init__()
        self.name = name
        self.client = client
        self.transport = transport(client, name)

    def emit(self, record):
        """Actually log the specified logging record.

        Overrides the default emit behavior of ``StreamHandler``.

        See: https://docs.python.org/2/library/logging.html#handler-objects

        :type record: :class:`logging.LogRecord`
        :param record: The record to be logged.
        """
        message = super(CloudLoggingHandler, self).format(record)
        self.transport.send(record, message)


class CloudLogger(object):
    """Cloud Logger."""

    def __init__(self, name, client, labels=None):
        """The Cloud Logger.

        Args:
            name: The log name.
            client: The API client.
            labels: A dictionary of labels for the log entry.
        """
        self.name = name
        self.client = client
        self.labels = labels

    @property
    def project(self):
        """The client's project property."""
        return self.client.project

    @property
    def full_name(self):
        """The full log name."""
        return 'projects/%s/logs/%s' % (self.project, self.name)

    def _make_entry_resource(self, text=None, info=None, message=None,
                             labels=None, insert_id=None, severity=None,
                             http_request=None, timestamp=None):
        """Return a log entry resource of the appropriate type.

        Helper for :meth:`log_text`, :meth:`log_struct`, and :meth:`log_proto`.

        Only one of ``text``, ``info``, or ``message`` should be passed.

        :type text: str
        :param text: (Optional) text payload

        :type info: dict
        :param info: (Optional) struct payload

        :type message: Protobuf message or :class:`NoneType`
        :param message: protobuf payload

        :type labels: dict
        :param labels: (Optional) labels passed in to calling method.

        :type insert_id: str
        :param insert_id: (optional) unique ID for log entry.

        :type severity: str
        :param severity: (optional) severity of event being logged.

        :type http_request: dict
        :param http_request: (optional) info about HTTP request associated with
                             the entry

        :type timestamp: :class:`datetime.datetime`
        :param timestamp: (optional) timestamp of event being logged.

        :rtype: dict
        :returns: The JSON resource created.
        """
        resource = {
            'logName': self.full_name,
            'resource': {'type': 'global'},
        }

        if text is not None:
            resource['textPayload'] = text

        if info is not None:
            resource['jsonPayload'] = info

        if message is not None:
            as_json_str = MessageToJson(message)
            as_json = json.loads(as_json_str)
            resource['protoPayload'] = as_json

        if labels is None:
            labels = self.labels

        if labels is not None:
            resource['labels'] = labels

        if insert_id is not None:
            resource['insertId'] = insert_id

        if severity is not None:
            resource['severity'] = severity

        if http_request is not None:
            resource['httpRequest'] = http_request

        if timestamp is not None:
            resource['timestamp'] = _datetime_to_rfc3339(timestamp)

        return resource

    def log_text(self, text, client=None, labels=None, insert_id=None,
                 severity=None, http_request=None, timestamp=None):
        """API call:  log a text message via a POST request

        See:
        https://cloud.google.com/logging/docs/api/reference/rest/v2/entries/write

        :type text: str
        :param text: the log message.

        :type client: :class:`~google.cloud.logging.client.Client` or
                      ``NoneType``
        :param client: the client to use.  If not passed, falls back to the
                       ``client`` stored on the current logger.

        :type labels: dict
        :param labels: (optional) mapping of labels for the entry.

        :type insert_id: str
        :param insert_id: (optional) unique ID for log entry.

        :type severity: str
        :param severity: (optional) severity of event being logged.

        :type http_request: dict
        :param http_request: (optional) info about HTTP request associated with
                             the entry

        :type timestamp: :class:`datetime.datetime`
        :param timestamp: (optional) timestamp of event being logged.
        """
        logger_client = self.client
        if client:
            logger_client = client
        entry_resource = self._make_entry_resource(
            text=text, labels=labels, insert_id=insert_id, severity=severity,
            http_request=http_request, timestamp=timestamp)
        logger_client.write_entries([entry_resource])
