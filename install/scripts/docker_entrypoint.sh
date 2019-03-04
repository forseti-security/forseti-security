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
# --bucket <bucket>             the Forseti GCS bucket containing configuration files etc
# --log_level <info,debug,etc>  the Forseti server log level
# --run_server                  start the Forseti server
# --cron_schedule <schedule>    specify schedule to run the cron scheduler within docker (use in conjunction with --run_server)
# --services <list of services> over-ride default services "scanner model inventory explain notifier"
# --run_client                  just provide a container to run client commands
# --run_k8s_cronjob             flag to run as k8s CronJob. Start server, run the cronjob immediately and exit
# --sql_host <host ip>          over-ride k8s (CLOUDSQLPROXY_SERVICE_HOST), cos (localhost) default
# --sql_port <port>             over-ride k8s (CLOUDSQLPOXY_SERVICE_PORT), cos (3306) default

# Use cases
# k8s CronJob,  specify --bucket, --run_k8s_cronjob
# k8s Server,   specify --bucket, --run_server --cron_schedule
# k8s Client,   specify --bucket, --run_client
# cos Server,   specify --bucket, --run_server --cron_schedule
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
BUCKET=''
LOG_LEVEL=info
SERVICES="scanner model inventory explain notifier"
RUN_SERVER=false
RUN_CLIENT=false
RUN_K8S_CRONJOB=false # run the k8s cronjob one time, then stop
CRON_SCHEDULE='' # Used if running cron in docker container

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
        --run_k8s_cronjob )
            RUN_K8S_CRONJOB=true
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
        --cron_schedule )
            shift
            CRON_SCHEDULE=$1
            ;;
    esac
    shift # Move remaining args down 1 position
done


download_server_configuration_files(){
    # Note, run_forseti.sh also does this at start of each cron run.
    # Nevertheless, we still need to do this once before starting the server.

    # TODO There is an intermittent issue with gsutil error that anonymous user not authorized to access the bucket.
    # Problem with secret?
    # Timing issue? Would pausing a bit help in case the secret setup not completed (just a wild guess) ?
    echo 'GOOGLE_APPLICATION_CREDENTIALS='.${GOOGLE_APPLICATION_CREDENTIALS}
    [ -r ${GOOGLE_APPLICATION_CREDENTIALS} ] && echo "Credentials file exist" || echo "Credentials file does not exist"

    # Start with a clean slate
    rm -f /forseti-security/configs/forseti_conf_server.yaml
    rm -f /forseti-security/rules/*.yaml

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

client_cli_setup(){
# Store the Client CLI variables in /etc/profile.d/forseti_environment.sh
# so all ssh sessions will have access to them

local FILE="/etc/profile.d/forseti_environment.sh"
/bin/cat <<EOM >$FILE
export FORSETI_HOME=/forseti-security
export FORSETI_CLIENT_CONFIG=${BUCKET}/configs/forseti_conf_client.yaml
EOM

# Source the environment variable script in .bashrc so it'ss sourced  automatically
# when users start a bash session
echo '. /etc/profile.d/forseti_environment.sh' >> ~/.bashrc
}

create_server_env_script(){
# Create env script used by run_forseti.sh
# Ref. https://github.com/GoogleCloudPlatform/forseti-security/blob/5e8b511cc26efe61894a99a81852794541416403/deployment-templates/compute-engine/server/forseti-instance-server.py#L251

# run_forseti.sh has hard coded /home/ubuntu/forseti_env.sh
# For now use /home/ubuntu as I don't know what might break in existing codebase if we change it
# todo Could we just export the variables instead of using the env file and let the source step fail in run_forseti.sh?

# Strip the 'gs://' portion of the bucket string
SCANNER_BUCKET=$(echo ${BUCKET} | cut -c 6-)

# Create /home/ubuntu if it doesnt exist
mkdir -p /home/ubuntu

local FILE="/home/ubuntu/forseti_env.sh"

/bin/cat <<EOM >$FILE
#!/bin/bash

export PATH=${PATH}:/usr/local/bin

# Forseti environment variables
export FORSETI_HOME=/forseti-security
export FORSETI_SERVER_CONF=/forseti-security/configs/forseti_conf_server.yaml
export SCANNER_BUCKET=${SCANNER_BUCKET}
EOM

}

set_container_cron_schedule(){
# Set up crontab if running cron within docker container and start cron
# Ref. https://github.com/GoogleCloudPlatform/forseti-security/blob/5e8b511cc26efe61894a99a81852794541416403/deployment-templates/compute-engine/server/forseti-instance-server.py#L267

# todo decide on user
USER=root # pre-existing code used ubuntu. Any issues here? Also we may want to get away from using root.

# Use flock to prevent rerun of the same cron job when the previous job is still running.
# If the lock file does not exist under the tmp directory, it will create the file and put a lock on top of the file.
# When the previous cron job is not finished and the new one is trying to run, it will attempt to acquire the lock
# to the lock file and fail because the file is already locked by the previous process.
# The -n flag in flock will fail the process right away when the process is not able to acquire the lock so we won't
# queue up the jobs.
# If the cron job failed the acquire lock on the process, it will log a warning message to syslog.

#(echo "${CRON_SCHEDULE} (/usr/bin/flock -n /home/ubuntu/forseti-security/forseti_cron_runner.lock /forseti-security/install/gcp/scripts/run_forseti.sh || echo '[forseti-security] Warning: New Forseti cron job will not be started, because previous Forseti job is still running.') 2>&1 | logger") | crontab -u $USER -
(echo "${CRON_SCHEDULE} (/usr/bin/flock -n /forseti-security/forseti_cron_runner.lock /forseti-security/install/gcp/scripts/run_forseti.sh || echo '[forseti-security] Warning: New Forseti cron job will not be started, because previous Forseti job is still running.') 2>&1 | logger") | crontab -u $USER -
echo "Added the run_forseti.sh to crontab under user $USER"

# todo best practices for docker are to run only 1 process, this is an additional process
# If it is appropriate to run cron in same container as server is debatable,
# This just proves the concept if it's whats wanted.
# CON Doing it this way means docker wont know if cron fails.
cron start &
}


start_server(){

# if short lived k8s CronJob, start as background process
if ${RUN_K8S_CRONJOB}; then
    forseti_server \
    --endpoint "localhost:50051" \
    --forseti_db "mysql://root@${SQL_HOST}:${SQL_PORT}/forseti_security" \
    --services ${SERVICES} \
    --config_file_path "/forseti-security/configs/forseti_conf_server.yaml" \
    --log_level=${LOG_LEVEL} \
    --enable_console_log &
# long lived server start as foreground process
# Note this will block further command processing in this script.
# Call this after all other setup has been completed.
else
    forseti_server \
    --endpoint "0.0.0.0:50051" \
    --forseti_db "mysql://root@${SQL_HOST}:${SQL_PORT}/forseti_security" \
    --services ${SERVICES} \
    --config_file_path "/forseti-security/configs/forseti_conf_server.yaml" \
    --log_level=${LOG_LEVEL} \
    --enable_console_log
fi

}

# Deprecated
# Instead call create_server_env_script()
# then call run_forseti.sh
run_k8s_cron_job(){
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

main(){

    if [[ ${LOG_LEVEL}='debug' ]]; then
        # Print commands to terminal
        set -x
    fi

    if ${RUN_SERVER}; then
        download_server_configuration_files

        # If cron schedule specified, create the crontab entry, after created needed env file
        if [[ !(-z ${CRON_SCHEDULE}) ]]; then
            create_server_env_script
            set_container_cron_schedule
        fi

        # Do this last as it blocks further commands in this script when running
        # server as foreground process
        start_server

    elif ${RUN_CLIENT}; then
        client_cli_setup

        # Client CLI is essentially a long running container for users to ssh into and
        # run ad hoc commands. (This is more for a k8s PoC, not sure on the value of running
        # the Client CLI in k8s as it's not providing a 'service' in the k8s environment.)
        # TODO This is a hack. Is there a better way to keep the container running?
        tail -f /dev/null

    elif ${RUN_K8S_CRONJOB}; then
        download_server_configuration_files
        start_server # will start as background process for k8s CronJob

        # Run the cron script, after creating needed env script
        create_server_env_script
        /forseti-security/install/gcp/scripts/run_forseti.sh
    fi
}


# Run this script
main
