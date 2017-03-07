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

"""A basic util that wraps logging.

Setup logging for Forseti Security based on deployment environment and
flags passed to the binaries.

If there are no flags passed to the Forseti tools, default logging behavior
is as follows:
  - Stackdriver/Cloud Logging, if querying metadata server succeeds. This means
    that Forseti is running on Compute Engine.
  - Otherwise, fall back to local logging.

If flags are passed, determine logging behavior as follows:
  - For --use-cloud-logging, enable Stackdriver/Cloud Logging (if available),
    otherwise fall back to local logging.
  - For --nouse-cloud-logging, only use local logging.
"""

import gflags as flags
import logging
import os

FLAGS = flags.FLAGS

flags.DEFINE_boolean('use-cloud-logging', True,
                  'Enable cloud logging, if available.')
flags.DEFINE_boolean('nouse-cloud-logging', False, 'Do not use cloud logging.')

class LogUtil(object):
    """Utility to wrap logging setup."""

    @classmethod
    def setup_logging(cls, module_name):
        """Setup logging configuration.

        Args:
            module_name: The name of the module to describe the log entry.

        Returns:
            An instance of the configured logger.
        """
        formatter = logging.Formatter(
                    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        my_logger = logging.getLogger(module_name)
        my_logger.addHandler(handler)
        if os.getenv('DEBUG'):
            my_logger.setLevel(logging.DEBUG)
        else:
            my_logger.setLevel(logging.INFO)
        return my_logger
