#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Block until the Forseti startup script has finished running.

MAX_WAIT=900

echo "Waiting for up to $MAX_WAIT seconds for Forseti to be ready."

for _ in $(seq 1 $MAX_WAIT); do
  if [[ -f /etc/profile.d/forseti_environment.sh ]]; then
    echo "Waiting for startup script to complete"
    sleep 30
    exit 0
  else
    sleep 10
  fi
done

echo "Forseti was not ready after $MAX_WAIT seconds!"
exit 1
