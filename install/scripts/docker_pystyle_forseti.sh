#!/bin/bash
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

trap 'return_code=$?' ERR

echo "Running pylint... "

docker exec -it build /bin/bash -c "pylint --rcfile=pylintrc google/ install/"

echo "Running flake8... "
# E501: Is line too long and should be handled by pylint.
# E711: Comparison to None and should be handled by pylint.
# E722: Bare except, it's been deemed OK by this project in certain cases.
# F841: Assigned but unused variable becuase flake/pycodestyle doesn't ignore _.
# W504: Line break after binary operator; have warning for before.
# W605: Invalid escape sequence. Pylint can specify which lines to ignore, while Flake8 cannot. Ignore this warning for
#       Flake8, so it will be caught by Pylint instead.
docker exec -it build /bin/bash -c "flake8 -v --doctests --max-line-length=80 --ignore=E501,E711,E722,F841,W504,W605 --exclude=*pb2*.py google/"

exit ${return_code}
