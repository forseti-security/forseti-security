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
  - For --use-cloud-logging, use Stackdriver/Cloud Logging (if available),
    otherwise fall back to local logging.
  - For --nouse-cloud-logging, only use local logging.

If there are no flags passed to the Forseti tools, default logging behavior
is as follows:
  - Stackdriver/Cloud Logging, if querying metadata server succeeds. This means
    that Forseti is running on Compute Engine.
  - Otherwise, fall back to local logging.
"""

import logging

import gflags as flags

from google.cloud.security.common.gcp_api import cloud_logging
from google.cloud.security.common.gcp_api import compute

FLAGS = flags.FLAGS
flags.DEFINE_boolean('use_cloud_logging', False,
                     'Use Cloud Logging, if available.')
flags.DEFINE_boolean('nouse_cloud_logging', False, 'Do not use Cloud Logging.')
flags.DEFINE_boolean('debug', False, 'Show DEBUG level logs.')

LOG_FORMAT = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
MODULE_PREFIX = 'google.cloud.security'

def get_logger(module_name):
    """Setup the basic logger.

    Args:
        module_name: The name of the mdule to describe the log entry.

    Returns:
        An instance of the configured logger.
    """
    formatter = logging.Formatter(LOG_FORMAT)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger_instance = logging.getLogger(module_name)
    logger_instance.addHandler(console_handler)
    logger_instance.setLevel(logging.INFO)

    return logger_instance

def configure_logger(module_name):
    """Additional logging configuration based on flags.

    Args:
        module_name: The name of the module for which to configure logging.
    """
    (is_gce, _) = compute.is_compute_engine_instance()
    should_use_cloud_logger = None
    cloud_handler = None

    # Use Cloud Logging if flag is set or if on GCE instance.
    if FLAGS.use_cloud_logging:
        should_use_cloud_logger = True

    # Force local logger.
    if FLAGS.nouse_cloud_logging:
        should_use_cloud_logger = False

    # Determine whether to use cloud logger based on environment.
    if should_use_cloud_logger is None:
        should_use_cloud_logger = is_gce

    if should_use_cloud_logger:
        formatter = logging.Formatter(LOG_FORMAT)
        cloud_handler = cloud_logging.CloudLoggingHandler(_get_cloud_logger())
        cloud_handler.setFormatter(formatter)

        logger_instance = logging.getLogger(module_name)
        logger_instance.addHandler(cloud_handler)

        if FLAGS.debug:
            logger_instance.setLevel(logging.DEBUG)

def _get_cloud_logger():
    """Gets the Cloud Logging Client."""
    return cloud_logging.LoggingClient()
