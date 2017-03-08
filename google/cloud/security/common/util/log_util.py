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

If flags are passed, determine logging behavior as follows:
  - For --use-cloud-logging, enable Stackdriver/Cloud Logging (if available),
    otherwise fall back to local logging.
  - For --nouse-cloud-logging, only use local logging.

If there are no flags passed to the Forseti tools, default logging behavior
is as follows:
  - Stackdriver/Cloud Logging, if querying metadata server succeeds. This means
    that Forseti is running on Compute Engine.
  - Otherwise, fall back to local logging.
"""

import gflags as flags
import logging
import os

from google.cloud import logging as cloud_logging
from google.cloud.security.common.gcp_api import compute

FLAGS = flags.FLAGS

flags.DEFINE_boolean('use_cloud_logging', True,
                     'Use Cloud Logging, if available.')
flags.DEFINE_boolean('nouse_cloud_logging', False, 'Do not use Cloud Logging.')


class LogUtil(object):
    """Utility to wrap logging setup."""

    def __init__(self, module_name):
        self._name = module_name
        self._logger = None

    @classmethod
    def get_logger(cls, module_name):
        """Setup logging configuration.

        Args:
            module_name: The name of the module to describe the log entry.

        Returns:
            An instance of the configured logger.
        """
        logging_instance = cls(module_name)
        if FLAGS.use_cloud_logging:
            logging_instance._attempt_setup_cloud_logger(force=True)
        elif FLAGS.nouse_cloud_logging:
            logging_instance._setup_local_logger()
        else:
            logging_instance._attempt_setup_cloud_logger()
        return logger_instance

    def _setup_local_logger(self, module_name):
        """Set up the local logger.

        Args:
            module_name: The name of the module to describe the log entry.
        """
        formatter = logging.Formatter(
                    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        local_logger = logging.getLogger(module_name)
        local_logger.addHandler(handler)
        if os.getenv('DEBUG'):
            local_logger.setLevel(logging.DEBUG)
        else:
            local_logger.setLevel(logging.INFO)
        self._logger = local_logger

    def _attempt_setup_cloud_logger(self, module_name, force=False):
        """Attempt to use the Cloud Logger.

        Try to setup the Cloud Logger if any of the following are true:
        1. force == True
        2. Successful query of metadata server (indicates we're running on GCE)

        If neither of the above are True, then setup the local logger.

        Args:
            module_name: The name of the module to describe the log entry.
            force: No matter what environment (GCE vs local), try to use
                Cloud Logger, if True.
        """
        is_gce = compute.ComputeClient.is_compute_engine_instance()
        if force or is_gce:
            logging_client = cloud_logging.Client()
            log_name = module_name
            instance_logger = logging_client.logger(log_name)
        else:
            instance_logger = cls._setup_local_logger(module_name)
        self._logger = instance_logger
