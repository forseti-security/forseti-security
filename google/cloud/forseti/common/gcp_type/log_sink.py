# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Stackdriver Log Sink/Export Resource.

See https://cloud.google.com/logging/docs/reference/v2/rest/v2/sinks
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class LogSink(resource.Resource):
    """Log Sink Resource."""

    def __init__(self, sink_id, destination, sink_filter,
                 include_children, writer_identity, parent, raw_json):
        """Initialize.

        Args:
            sink_id (str): The client-assigned log sink identifier.
            destination (str): The export destination.
            sink_filter (str): A log filter, only matching log entries are
                exported.
            include_children (bool): Whether to export logs from all the
                projects, folders, and billing accounts contained in the sink's
                parent resource. Does not apply to project-level sinks.
            writer_identity (str): An IAM identity under which Stackdriver
                Logging writes the exported entries to the destination.
            parent (Resource): The parent resource (project, folder,
                organization, billing account) of this sink.
            raw_json (str): The raw json string for the sink.

        """
        super(LogSink, self).__init__(
            resource_id=sink_id,
            resource_type=resource.ResourceType.LOG_SINK,
            name='{}/sinks/{}'.format(parent.name, sink_id),
            display_name=sink_id,
            parent=parent)
        self.destination = destination
        self.sink_filter = sink_filter
        self.include_children = include_children
        self.writer_identity = writer_identity
        self.raw_json = raw_json

    @classmethod
    def from_dict(cls, parent, sink_dict):
        """Returns a new LogSink object from dict.

        Args:
            parent (Resource): The parent resource of this sink.
            sink_dict (dict): Log Sink dictionary.

        Returns:
            LogSink: A new LogSink object.
        """
        return cls(
            sink_id=sink_dict.get('name', ''),
            destination=sink_dict.get('destination', ''),
            sink_filter=sink_dict.get('filter', ''),
            include_children=sink_dict.get('includeChildren', False),
            writer_identity=sink_dict.get('writerIdentity', ''),
            parent=parent,
            raw_json=json.dumps(sink_dict, sort_keys=True)
        )

    @staticmethod
    def from_json(parent, sink_json):
        """Returns a new LogSink object from a JSON encoding.

        Args:
            parent (Resource): The parent resource of this sink.
            sink_json (str): The JSON encoding of the log sink.

        Returns:
            LogSink: A new LogSink object.
        """
        sink_dict = json.loads(sink_json)
        return LogSink.from_dict(parent, sink_dict)
