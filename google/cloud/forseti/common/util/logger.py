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

"""A basic util that wraps logging.

Setup logging for Forseti Security. Logs to console and syslog.
"""

import logging
import logging.handlers

DEFAULT_LOG_FMT = ('%(asctime)s %(levelname)s '
                   '%(name)s(%(funcName)s): %(message).1024s')
SYSLOG_LOG_FMT = ('[forseti-security] %(levelname)s '
                  '%(name)s(%(funcName)s): %(message).1024s')
LOGGERS = {}
LOGLEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARN,
    'error': logging.ERROR,
}
LOGLEVEL = logging.INFO
LOG_TO_CONSOLE = False


def get_logger(module_name):
    """Setup the logger.

    Args:
        module_name (str): The name of the mdule to describe the log entry.

    Returns:
        logger: An instance of the configured logger.
    """
    # TODO: Move this into a configuration file.
    syslog_handler = logging.handlers.SysLogHandler()
    syslog_handler.setFormatter(logging.Formatter(SYSLOG_LOG_FMT))

    logger_instance = logging.getLogger(module_name)
    logger_instance.addHandler(syslog_handler)
    logger_instance.setLevel(LOGLEVEL)

    if LOG_TO_CONSOLE:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FMT))
        logger_instance.addHandler(console_handler)

    LOGGERS[module_name] = logger_instance
    return logger_instance


def _map_logger(func):
    """Map function to current loggers.

    Args:
        func (function): Function to call on every logger.
    """
    for logger in LOGGERS.itervalues():
        func(logger)


def set_logger_level(level):
    """Modify log level of existing loggers as well as the default
       for new loggers.

    Args:
        level (int): The log level to set the loggers to.
    """
    # pylint: disable=global-statement
    global LOGLEVEL
    LOGLEVEL = level
    _map_logger(lambda logger: logger.setLevel(level))


def enable_console_log():
    """Enable console logging for all the new loggers and add console
    handlers to all the existing loggers."""

    # pylint: disable=global-statement
    global LOG_TO_CONSOLE
    LOG_TO_CONSOLE = True
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FMT))
    _map_logger(lambda logger: logger.addHandler(console_handler))


def set_logger_level_from_config(level_name):
    """Set the logger level from a config value.

    Args:
        level_name (str): The log level name. The accepted values are
            in the LOGLEVELS variable.
    """
    set_logger_level(LOGLEVELS.get(level_name, LOGLEVEL))
