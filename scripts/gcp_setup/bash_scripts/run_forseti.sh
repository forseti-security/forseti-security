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

source /home/ubuntu/forseti_env.sh

# Put the config files in place.
gsutil cp gs://$SCANNER_BUCKET/configs/forseti_conf.yaml $FORSETI_CONF
gsutil cp -r gs://$SCANNER_BUCKET/rules $FORSETI_HOME/

if [ ! -f "$FORSETI_CONF" ]; then
    echo "Forseti conf not found, exiting."
    exit 1
fi

# inventory command
forseti inventory create
INVENTORY=$(forseti inventory get_latest)
if [ -z "${INVENTORY}" ]; then
    echo "No inventory exists; exiting."
    exit 1
fi
INVENTORY_ID=$(echo "${INVENTORY}" | sed -nE 's/.*"id": ([0-9]+),.*/\1/p')
echo "Latest inventory id ${INVENTORY_ID}"

MODEL_INFO=$(forseti model create inventory model_${INVENTORY_ID} --id ${INVENTORY_ID})
MODEL_HANDLE=$(echo "${MODEL_INFO}" | sed -nE 's/.*"handle": "([0-9a-z]+)",.*/\1/p')
echo "Created model ${MODEL_HANDLE}"

forseti model use ${MODEL_HANDLE}
echo "Using model ${MODEL_HANDLE}"

# scanner command TBD
# forseti scanner run ${FORSETI_HOME}/configs
