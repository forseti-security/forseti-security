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

"""Base pipeline to load data into inventory."""


# pylint: disable=too-few-public-methods
# TODO: Look into improving to prevent using the disable.
class _BasePipeline(object):
    """Base client for a specified GCP API and credentials."""

    def __init__(self, name, cycle_timestamp, configs, gcp_api_client, dao,
                 transform_util):
        """Constructor for the base pipeline.

        Args:
            name: String of the resource loaded by the pipeline.
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            gcp_api_client: GCP API client object.
            dao: Data access object.

        Returns:
            None
        """
        self.name = name
        self.cycle_timestamp = cycle_timestamp
        self.configs = configs
        self.gcp_api_client = gcp_api_client
        self.dao = dao
        self.transform_util = transform_util
