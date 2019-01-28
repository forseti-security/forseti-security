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

# UNDER DEVELOPMENT, FOR PROOF OF CONCEPT PURPOSES ONLY
# This script serves as the entrypoint for starting Forseti server or client in a Docker container.
# Ref. https://docs.docker.com/engine/reference/builder/#entrypoint

# Usage
# <sudo> docker exec ${CONTAINER_ID} /forseti-security/install/scripts/docker_entrypoint.sh
# --bucket <bucket>                             the Forseti GCS bucket containing configuration files etc
# --log_level <info,debug,etc>                  the Forseti server log level
# --run_server                                  start the Forseti server
# --services <list of services>                 over-ride default services "scanner model inventory explain notifier"
# --run_client                                  just provide a container to run client commands
# --run_cronjob                                 run the cronjob immediately after starting server, for k8s CronJob
# --sql_host <host ip>                          over-ride k8s (CLOUDSQLPROXY_SERVICE_HOST), cos (localhost) default
# --sql_port <port>                             over-ride k8s (CLOUDSQLPOXY_SERVICE_PORT), cos (3306) default

# Use cases
# k8s CronJob,  specify --bucket, --run_server, --run_cronjob
# k8s Server,   specify --bucket, --run_server
# k8s Client,   specify --bucket, --run_client
# cos Server,   specify --bucket, --run_server
# cos Client,   specify --bucket, --run_client

# Note for k8s CronJob or k8s Server the k8s Cloud SQL Proxy Service must be named "cloudsqlproxy" else the
# k8s environment variable names will change from what this script expects
# CLOUDSQLPROXY_SERVICE_HOST
# CLOUDSQLPROXY_SERVICE_PORT
# TODO refactor this; hard coding the k8s variable names is fragile

# TODO Error handling in all functions
# For now, just stop the script if an error occurs
set -e

# Declare variables and set default values
BUCKET=
LOG_LEVEL=info
SERVICES="scanner model inventory explain notifier"
RUN_SERVER=false
RUN_CLIENT=false
RUN_CRONJOB=false

# Use these SQL defaults which work for running on a Container Optimized OS (cos) with a CloudSQL Proxy sidecar container
SQL_HOST=localhost
SQL_PORT=3306

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
        --bucket )
            shift
            BUCKET=$1
            ;;
        --log_level )
            shift
            LOG_LEVEL=$1
            ;;
        --run_server )
            RUN_SERVER=true
            ;;
        --run_cronjob )
            RUN_CRONJOB=true
            ;;
        --run_client )
            RUN_CLIENT=true
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
    esac
    shift # Move remaining args down 1 position
done

download_server_configuration_files(){
    # Download config files from GCS
    # Use gsutil -DD debug flag if log level is debug
    if [[ ${LOG_LEVEL} = "debug" ]]; then
        gsutil -DD cp ${BUCKET}/configs/forseti_conf_server.yaml /forseti-security/configs/forseti_conf_server.yaml
        gsutil -DD cp -r ${BUCKET}/rules /forseti-security/
    else
        gsutil cp ${BUCKET}/configs/forseti_conf_server.yaml /forseti-security/configs/forseti_conf_server.yaml
        gsutil cp -r ${BUCKET}/rules /forseti-security/
    fi

}

# TODO
client_cli_setup(){
    echo "client_cli_setup is not implemented yet."

    # Store the variables in /etc/profile.d/forseti_environment.sh
    # so all the users will have access to them
    echo "echo 'export FORSETI_HOME=/forseti-security
    export FORSETI_CLIENT_CONFIG=${BUCKET}/configs/forseti_conf_client.yaml
    ' >> /etc/profile.d/forseti_environment.sh" | sh
}

# TODO Should this be started as a background or foreground process?
# For cron job we start as a background process and the container finishes when the cronjob completes
# For long running server, starting as a background process causes the container to keep re-starting
# I think we need to start as background for cronjob and foreground for long running server
start_server(){

if ${RUN_CRONJOB}; then # short lived cronjob, start as background process
    forseti_server \
    --endpoint "localhost:50051" \
    --forseti_db "mysql://root@${SQL_HOST}:${SQL_PORT}/forseti_security" \
    --services ${SERVICES} \
    --config_file_path "/forseti-security/configs/forseti_conf_server.yaml" \
    --log_level=${LOG_LEVEL} &
    #--enable_console_log

else # long lived server, start as foreground process
    forseti_server \
    --endpoint "localhost:50051" \
    --forseti_db "mysql://root@${SQL_HOST}:${SQL_PORT}/forseti_security" \
    --services ${SERVICES} \
    --config_file_path "/forseti-security/configs/forseti_conf_server.yaml" \
    --log_level=${LOG_LEVEL}
    #--enable_console_log
fi

}

run_cron_job(){
    # Below cut and paste from run_forseti.sh
    # Ideally just call run_forseti.sh directly but for now its not quite right for us in GKE
    # due to the way it sources environment variables

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

    if [[ "$MODEL_STATUS" == "BROKEN" ]]
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

    # End cut and paste from run_forseti.sh
}

#error_exit()
#{
#	echo "$1" 1>&2
#	exit 1
#}

main(){

    if [[ ${LOG_LEVEL}='debug' ]]; then
        # Print commands to terminal
        set -x
    fi

    # Run server or client; not both in same container
    if ${RUN_SERVER}; then
        download_server_configuration_files
        start_server
    elif ${RUN_CLIENT}; then
        client_cli_setup

        # Client CLI is essentially a long running container for users to ssh into and
        # run ad hoc commands. (This is more for a k8s PoC, not sure on the value of running
        # the Client CLI in k8s and its not providing a 'service' in the k8s environment.)
        # TODO This is a hack. Is there a better way to keep the container running?
        #sleep infinity & doesnt work
        #try
        tail -f /dev/null
    fi

    if ${RUN_CRONJOB}; then
        run_cron_job
    fi
}


# Run this script
main
