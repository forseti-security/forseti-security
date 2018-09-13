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


# set -x enables a mode of the shell where all executed commands are printed to the terminal.
# With this  enabled, we should not put anything private/secret in the commands called because
# they will be logged.
set -x

# Put the config files in place.
sudo gsutil cp gs://${SCANNER_BUCKET}/configs/forseti_conf_server.yaml ${FORSETI_SERVER_CONF}
sudo gsutil cp -r gs://${SCANNER_BUCKET}/rules ${FORSETI_HOME}/

if [ ! -f "${FORSETI_SERVER_CONF}" ]; then
    echo "Forseti conf not found, exiting."
    exit 1
fi

# Restart the server to avoid auth problem, this is a temp fix to
# https://github.com/GoogleCloudPlatform/forseti-security/issues/1832
sudo systemctl restart forseti.service

# Wait until the service is started
sleep 10s

# Reload the server configuration settings
forseti server configuration reload

# Set the output format to json
forseti config format json

# Purge inventory.
# Use retention_days from configuration yaml file.
forseti inventory purge

# Run inventory command
MODEL_NAME=$(/bin/date -u +%Y%m%dT%H%M%S)
echo "Running Forseti inventory."
forseti inventory create --import_as ${MODEL_NAME}
echo "Finished running Forseti inventory."
sleep 5s

GET_MODEL_STATUS="forseti model get ${MODEL_NAME} | python -c \"import sys, json; print json.load(sys.stdin)['status']\""
MODEL_STATUS=`eval $GET_MODEL_STATUS`

if [ "$MODEL_STATUS" == "BROKEN" ]
    then
        echo "Model is broken, please contact discuss@forsetisecurity.org for support."
        exit
fi

# Run model command
echo "Using model ${MODEL_NAME} to run scanner"
forseti model use ${MODEL_NAME}
# Sometimes there's a lag between when the model
# successfully saves to the database.
sleep 10s
echo "Forseti config: $(forseti config show)"

# Run scanner command
echo "Running Forseti scanner."
forseti scanner run
echo "Finished running Forseti scanner."
sleep 10s

# Run notifier command
echo "Running Forseti notifier."
forseti notifier run
echo "Finished running Forseti notifier."
sleep 10s

# Clean up the model tables
echo "Cleaning up model tables"
forseti model delete ${MODEL_NAME}
