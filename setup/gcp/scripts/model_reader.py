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

"""Model reader."""

import re
import sys


if __name__ == '__main__':
    for line in sys.stdin:
        if re.match('^handle: ', line):
            line = line.replace('"', '')
            handle = line.split('handle: ')[1]
            sys.stdout.write(handle)
            sys.stdout.flush()
            break
