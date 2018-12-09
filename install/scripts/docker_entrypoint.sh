#!/bin/bash
# Copyright 2018 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Versisn 2.0 (the "License");
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

# Usage
# (sudo if needed) docker exec ${CONTAINER_ID} /forseti-security/install/scripts/docker_entrypoint.sh ${BUCKET}

# UNDER DEVELOPMENT. For now basic functionality, just starts Forseti Server.
# This script serves as the entrypoint for starting Forseti server in a Docker container.
# Ref. https://docs.docker.com/engine/reference/builder/#entrypoint
#
# This script assumes it's running in a container on a GCE Container Optimized OS VM
# that is already authorized with the forseti service account.

# TODO named arg and arg validation
# TODO arg to control which services to start (default to server for now)
BUCKET=$1

# Download config files
# -DD optional gsutil debugging
# TODO switch debugging on/off via env var
gsutil -DD cp ${BUCKET}/configs/forseti_conf_server.yaml /forseti-security/configs/forseti_conf_server.yaml
gsutil -DD cp -r ${BUCKET}/rules /forseti-security/

# TODO Error handling for gsutil cp

# Start Forseti server
# This requires the cloud sql proxy (side car) container is running on 127.0.0.1:3306
# TODO switch debugging on/off via env var
forseti_server \
--endpoint "localhost:50051" \
--forseti_db "mysql://root@127.0.0.1:3306/forseti_security" \
--services scanner model inventory explain notifier \
--config_file_path "/forseti-security/configs/forseti_conf_server.yaml" \
--log_level=debug \
#--enable_console_log #turn off for now

# Below cut and paste from run_forseti.sh ######################################
# Ideally just call run_forseti.sh directly but for now its not quite right for us in GKE

# Wait until the service is started
sleep 10s

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
scanner_command=`forseti scanner run`
scanner_index_id=`echo ${scanner_command} | grep -o -P '(?<=(ID: )).*(?=is created)'`
echo "Finished running Forseti scanner."
sleep 10s

# Run notifier command
echo "Running Forseti notifier."
forseti notifier run --scanner_index_id ${scanner_index_id}
echo "Finished running Forseti notifier."
sleep 10s

# Clean up the model tables
echo "Cleaning up model tables"
forseti model delete ${MODEL_NAME}
