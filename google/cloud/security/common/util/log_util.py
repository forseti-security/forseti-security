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

Setup logging for Forseti Security. Logs to console and syslog.
"""

import logging
import logging.handlers

LOG_FORMAT = '%(asctime)s %(name)-12s %(levelname)-8s %(funcName)s %(message)s'


def get_logger(module_name):
    """Setup the logger.

    Args:
        module_name: The name of the mdule to describe the log entry.

    Returns:
        An instance of the configured logger.
    """
    # TODO: Move this into a configuration file.
    formatter = logging.Formatter(LOG_FORMAT)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    syslog_handler = logging.handlers.SysLogHandler()
    syslog_handler.setFormatter(formatter)
    logger_instance = logging.getLogger(module_name)
    logger_instance.addHandler(console_handler)
    logger_instance.addHandler(syslog_handler)
    logger_instance.setLevel(logging.INFO)
    return logger_instance
