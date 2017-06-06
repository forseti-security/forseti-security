#!/bin/bash
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

# A script to perform the linting of python code submits.

echo "Running $(which pylint).\n"

echo "Pylint version: $(pip show pylint).\n"

# The disables specified allow us to have 'I' level messages, just
# not the ones specified.
PYTHONPATH=./ \
  pylint google/ \
  --rcfile=./pylintrc

if [ $? -ne 0 ]; then
  echo "Oops, pylint had errors.\n"
  exit 1
else
  echo "Success, pylint had no errors.\n"
  exit 0
fi
