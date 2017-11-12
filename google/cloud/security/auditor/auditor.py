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

"""Forseti Auditor."""

import gflags as flags

from google.apputils import app

from google.cloud.security import config
from google.cloud.security.auditor import other


# Setup flags
FLAGS = flags.FLAGS

# Hack to make the test pass due to duplicate flag error.
# TODO: Find a way to remove this try/except, possibly dividing the tests
# into different test suites.
try:
    flags.DEFINE_string(
        'forseti_config',
        '/home/ubuntu/forseti-security/configs/forseti_conf.yaml',
        'Fully qualified path and filename of the Forseti config file.')
except flags.DuplicateFlagError:
    pass


def main(_):
    if not config.FORSETI_CONFIG:
        config.FORSETI_CONFIG = config.from_file(FLAGS.forseti_config)


if __name__ == '__main__':
    app.run()
