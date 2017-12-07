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


# Try to guess if a user has invoked this unexpectedly, and print info.
if [[ -z "${GSUITE_ADMIN_CREDENTIAL_PATH}" ]]; then
    echo "This script is a piece of the Forseti deployment infrastructure."
    echo "It is meant to be run from the Forseti VM that gets deployed by"
    echo "Deployment Manager (either using 'gcloud deployment-manager' or"
    echo "setup_forseti.py). This script expects either root or"
    echo "unauthenticated sudo privileges on the target VM."
fi

set -o errexit
set -o nounset

# Reference all required bash variables prior to running. Due to 'nounset', if
# a caller fails to export the following expected environmental variables, this
# script will fail immediately rather than partially succeeding.
echo "Cloud SQL Instance Connection string: ${SQL_INSTANCE_CONN_STRING}"
echo "SQL port: ${SQL_PORT}"
echo "Forseti DB name: ${FORSETI_DB_NAME}"
echo "G Suite admin email: ${GSUITE_ADMIN_EMAIL}"
echo "Root resource ID: ${ROOT_RESOURCE_ID}"
if ! [[ -f $GSUITE_ADMIN_CREDENTIAL_PATH ]]; then
    echo "Could not find gsuite admin credentials." >&2
    exit 1
fi


SQL_SERVER_LOCAL_ADDRESS="mysql://root@127.0.0.1:${SQL_PORT}"
FORSETI_SERVICES="playground explain inventory model scanner"


FORSETI_COMMAND="$(which forseti_server) --endpoint '[::]:50051'"
FORSETI_COMMAND+=" --forseti_db ${SQL_SERVER_LOCAL_ADDRESS}/${FORSETI_DB_NAME}"
FORSETI_COMMAND+=" --gsuite_private_keyfile ${GSUITE_ADMIN_CREDENTIAL_PATH}"
FORSETI_COMMAND+=" --gsuite_admin_email ${GSUITE_ADMIN_EMAIL}"
FORSETI_COMMAND+=" --root_resource_id ${ROOT_RESOURCE_ID}"
FORSETI_COMMAND+=" --services ${FORSETI_SERVICES}"


SQL_PROXY_COMMAND="$(which cloud_sql_proxy)"
SQL_PROXY_COMMAND+=" -instances=${SQL_INSTANCE_CONN_STRING}=tcp:${SQL_PORT}"


# Cannot use "read -d" since it returns a nonzero exit status.
API_SERVICE="$(cat << EOF
[Unit]
Description=Forseti API Server
[Service]
Restart=always
RestartSec=3
ExecStart=$FORSETI_COMMAND
[Install]
WantedBy=multi-user.target
Wants=cloudsqlproxy.service
EOF
)"
echo "$API_SERVICE" > /tmp/forseti.service
sudo mv /tmp/forseti.service /lib/systemd/system/forseti.service


SQL_PROXY_SERVICE="$(cat << EOF
[Unit]
Description=Cloud SQL Proxy
[Service]
Restart=always
RestartSec=3
ExecStart=$SQL_PROXY_COMMAND
[Install]
WantedBy=forseti.service
EOF
)"
echo "$SQL_PROXY_SERVICE" > /tmp/cloudsqlproxy.service
sudo mv /tmp/cloudsqlproxy.service /lib/systemd/system/cloudsqlproxy.service


# Define a foreground runner. This runner will start the CloudSQL
# proxy and block on the Forseti API server.
FOREGROUND_RUNNER="$(cat << EOF
$SQL_PROXY_COMMAND &&
$FORSETI_COMMAND
EOF
)"
echo "$FOREGROUND_RUNNER" > /tmp/forseti-foreground.sh
chmod 755 /tmp/forseti-foreground.sh
sudo mv /tmp/forseti-foreground.sh /usr/bin/forseti-foreground.sh


echo "Forseti services are now registered with systemd. Services can be started"
echo "immediately by running the following:"
echo ""
echo "    systemctl start cloudsqlproxy"
echo "    systemctl start forseti"
echo ""
echo "Additionally, the Forseti server can be run in the foreground by using"
echo "the foreground runner script: /usr/bin/forseti-foreground.sh"
