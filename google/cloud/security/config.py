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

"""Configuration handling.

Some ideas borrowed from https://github.com/kdart/pycopia/blob/master/core/pycopia/basicconfig.py.

Calling setup_config() with a yaml file will create a dictionary that
maps attributes to the underlying dictionary. For example:

config = ForsetiConfig.from_file('/path/to/config.yaml')

where config.yaml contains:

common:
  prop1: x
  prop2: y
module1:
  prop1: z

Then the config properties can be accessed as follows:

config.prop1 => 'x'
config.module1.prop1 => 'z'
"""

import os
import sys

from pprint import pformat

import yaml

from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class ConfigHolder(dict):
    """Holds the Config values."""

    def __init__(self, init, name=None):
        name = name or self.__class__.__name__.lower()
        dict.__init__(self, init)
        dict.__setattr__(self, '_name', name)

    def __getstate__(self):
        return '%s(%s)' % (self.__class__.__name__, self.__dict__.items())

    def __setstate__(self, items):
        for key, val in items:
            self.__dict__[key] = val

    def __getitem__(self, name):
        try:
            return super(ConfigHolder, self).__getitem__(name)
        except:
            LOGGER.warn('Missing config: %s' % name)
            return None

    def __setitem__(self, key, value):
        return super(ConfigHolder, self).__setitem__(key, value)

    __getattr__ = __getitem__
    __setattr__ = __setitem__


class ForsetiConfig(object):
    """ForsetiConfig."""

    def __init__(self, config_path):
        self.config_path = config_path
        self.root_config = ConfigHolder({}, 'all')

    @classmethod
    def from_file(cls, config_path):
        cls = ForsetiConfig(config_path)
        cls.setup_config()
        return cls

    @classmethod
    def from_envvar(cls, varname='FORSETI_CONFIG'):
        config_path = os.environ.get(varname)
        if config_path:
            return ForsetiConfig.from_file(config_path)
        return None

    def __repr__(self):
        """__repr__

        Returns:
            str: The __repr__
        """
        return 'ForsetiConfig:\n%s' % pformat(self.root_config, indent=2)

    def setup_config(self):
        try:
            all_config = file_loader.read_and_parse_file(self.config_path)
        except IOError:
            LOGGER.error('Unable to open config file %s' % self.config_path)
            sys.exit(1)

        # Treat top level properties as "sections"
        for key in all_config:
            if key == 'global':
                config_prop = 'common'
            else:
                config_prop = key
            self.root_config[config_prop] = ConfigHolder(all_config[key], config_prop)


FORSETI_CONFIG = ForsetiConfig.from_envvar()
