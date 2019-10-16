#!/bin/bash
# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

# UNDER DEVELOPMENT, FOR PROOF OF CONCEPT PURPOSES ONLY
# This script serves as the entrypoint for starting Forseti server or client in a Docker container.
# Ref. https://docs.docker.com/engine/reference/builder/#entrypoint

# Usage
# <sudo> docker exec ${CONTAINER_ID} /forseti-security/install/scripts/docker_entrypoint.sh
# --log_level <info,debug,etc>  the Forseti server log level
# --run_server                  start the Forseti server
# --services <list of services> over-ride default services "scanner model inventory explain notifier"
# --run_client                  just provide a container to run client commands
# --sql_host <host ip>          over-ride k8s (CLOUDSQLPROXY_SERVICE_HOST), cos (localhost) default
# --sql_port <port>             over-ride k8s (CLOUDSQLPOXY_SERVICE_PORT), cos (3306) default

# Use cases

# k8s Server,   --run_server
# k8s Client,   --run_client


# TODO Error handling in all functions
# For now, just stop the script if an error occurs
set -e

LOG_LEVEL=info
SERVICES="scanner model inventory explain notifier"
RUN_SERVER=false
RUN_CLIENT=false
RUN_TEST=false

# Use these SQL defaults which work for running on a Container Optimized OS (cos) with a CloudSQL Proxy sidecar container
SQL_HOST=127.0.0.1
SQL_PORT=3306

SERVER_HOST=127.0.0.1
SERVER_PORT=50051

# Check if the k8s cloud sql proxy environment variables have been set, if so
# overwrite our cloud sql variables with their contents
if [[ !(-z ${CLOUDSQLPROXY_SERVICE_HOST}) ]]; then
    SQL_HOST=${CLOUDSQLPROXY_SERVICE_HOST}
fi

if [[ !(-z ${CLOUDSQLPROXY_SERVICE_PORT}) ]]; then
    SQL_PORT=${CLOUDSQLPROXY_SERVICE_PORT}
fi

# Note if sql_host and sql_port are specified as script command line arguments they will
# take precedence further below when we read in the command line args

# Read command line arguments
while [[ "$1" != "" ]]; do
    # Process next arg at position $1
    case $1 in
        --log_level )
            shift
            LOG_LEVEL=$1
            ;;
        --run_server )
            RUN_SERVER=true
            ;;
        --run_client )
            RUN_CLIENT=true
            ;;
        --run_test )
            RUN_TEST=true
            ;;
        --services )
            shift
            SERVICES=$1
            ;;
        --sql_host )
            shift
            SQL_HOST=$1
            ;;
        --sql_port )
            shift
            SQL_PORT=$1
            ;;
        --server_host )
            shift
            SERVER_HOST=$1
            ;;
        --server_port )
            shift
            SERVER_PORT=$1
            ;;
    esac
    shift # Move remaining args down 1 position
done

start_server(){

    forseti_server \
    --endpoint ${SERVER_HOST}:${SERVER_PORT} \
    --forseti_db "mysql+pymysql://${SQL_DB_USER}:${SQL_DB_PASSWORD}@${SQL_HOST}:${SQL_PORT}/forseti_security" \
    --services ${SERVICES} \
    --config_file_path "/forseti-security/forseti_conf_server.yaml" \
    --log_level=${LOG_LEVEL} \
    --enable_console_log
}

# Deprecated
# Instead call create_server_env_script()
# then call run_forseti.sh
run_forseti_job(){
    # Below cut and paste from run_forseti.sh
    # Ideally just call run_forseti.sh directly but for now its not quite right for us in GKE
    # due to the way it sources environment variables

    # Wait until the service is started
    sleep 10s
    
    # Set the output format to json
    forseti config format json
    forseti config endpoint ${SERVER_HOST}:${SERVER_PORT}

    # Purge inventory.
    # Use retention_days from configuration yaml file.
    forseti inventory purge

    # Run inventory command
    MODEL_NAME=$(/bin/date -u +%Y%m%dT%H%M%S)
    echo "Running Forseti inventory."
    forseti inventory create --import_as ${MODEL_NAME}

    echo "Finished running Forseti inventory."
    sleep 5s

    echo "Obtaining model ${MODEL_NAME}"
    forseti model get ${MODEL_NAME}

    echo "Finished Obtaining model ${MODEL_NAME}"

    echo "Checking model status"
    GET_MODEL_STATUS="forseti model get ${MODEL_NAME} | python3 -c \"import sys, json; print(json.load(sys.stdin)['status'])\""
    MODEL_STATUS=`eval $GET_MODEL_STATUS`

    if [[ "$MODEL_STATUS" == "BROKEN" ]]
        then
            echo "Model is broken, please contact discuss@forsetisecurity.org for support."
            exit
    fi

    echo "Finished checking model status"

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

    # End cut and paste from run_forseti.sh
}

run_test(){
    
    # Set the output format to json
    forseti config format json

    # Set the endpoint
    forseti config endpoint $FORSETI_SERVER_SERVICE_HOST:$FORSETI_SERVER_SERVICE_PORT
    
    result=$(forseti inventory list)
    
    if [[ -z "$result" ]]; then
        exit 0
    fi
    
    echo $result | grep "Error communicating to the Forseti server."
    if [[ $? == 0 ]]; then
        exit 1 
    fi

    exit 0
}

main(){

    if [[ ${LOG_LEVEL}='debug' ]]; then
        # Print commands to terminal
        set -x
    fi

    if ${RUN_SERVER}; then
        start_server

    elif ${RUN_CLIENT}; then
        run_forseti_job
    
    elif ${RUN_TEST}; then
        run_test
    
    fi
        
}


# Run this script
main
