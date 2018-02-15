# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Forseti installer config object."""

import datetime

from setup.gcp.installer.util.constants import CONFIG_FILENAME_FMT


class Config(object):
    """Forseti installer config object."""

    # Class variables initialization
    datetimestamp = None
    timestamp = None
    force_no_cloudshell = None
    config_filename = None
    advanced_mode = None
    dry_run = None
    bucket_location = None
    template_type = None

    def __init__(self, **kwargs):
        """Initialize.

        Args:
            kwargs (dict): The kwargs.
        """

        self.datetimestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        self.timestamp = self.datetimestamp[8:]
        self.force_no_cloudshell = bool(kwargs.get('no_cloudshell'))
        self.config_filename = (kwargs.get('config') or
                                CONFIG_FILENAME_FMT.format(
                                    self.datetimestamp))
        self.advanced_mode = bool(kwargs.get('advanced'))
        self.dry_run = bool(kwargs.get('dry_run'))
        self.bucket_location = kwargs.get('gcs_location') or 'us-central1'
