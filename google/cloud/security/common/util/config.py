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
"""

from __future__ import print_function

import sys

import yaml

#from google.cloud.security.common.util import file_loader


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
            print('Missing config: %s' % name)
            return None

    def __setitem__(self, key, value):
        return super(ConfigHolder, self).__setitem__(key, value)

    __getattr__ = __getitem__
    __setattr__ = __setitem__


def merge_config(filename, global_env=None):
    try:
        #all_config = file_loader.read_and_parse_file(filename)
        with open(filename) as config_fp:
            all_config = yaml.safe_load(config_fp)
    #except IOError:
    except:
        print('Unable to open config file %s' % filename)
        sys.exit(1)

    # Treat top level properties as "sections"
    toplevel = ConfigHolder({}, 'all')

    for key in all_config:
        if key == 'global':
            config_prop = 'common'
        else:
            config_prop = key
        toplevel[config_prop] = ConfigHolder(all_config[key], config_prop)

    # TODO: merge global env vars

    return toplevel

fc = merge_config('/Users/carise/Development/forseti-security/configs/forseti_conf.yaml')
