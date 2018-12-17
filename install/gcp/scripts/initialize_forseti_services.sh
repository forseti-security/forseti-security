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

set -o errexit
set -o nounset

# Reference all required bash variables prior to running. Due to 'nounset', if
# a caller fails to export the following expected environmental variables, this
# script will fail immediately rather than partially succeeding.
echo "Cloud SQL Instance Connection string: ${SQL_INSTANCE_CONN_STRING}"
echo "SQL port: ${SQL_PORT}"
echo "Forseti DB name: ${FORSETI_DB_NAME}"

if ! [[ -f $FORSETI_SERVER_CONF ]]; then
    echo "Could not find the configuration file: ${FORSETI_SERVER_CONF}." >&2
    exit 1
fi

# We had issue creating DB user through deployment template, if the issue is
# resolved in the future, we should create a forseti db user instead of using
# root.
# https://github.com/GoogleCloudPlatform/forseti-security/issues/921
SQL_SERVER_LOCAL_ADDRESS="mysql://root@127.0.0.1:${SQL_PORT}"
FORSETI_SERVICES="explain inventory model scanner notifier"

FORSETI_COMMAND="$(which forseti_server) --endpoint '[::]:50051'"
FORSETI_COMMAND+=" --forseti_db ${SQL_SERVER_LOCAL_ADDRESS}/${FORSETI_DB_NAME}?charset=utf8"
FORSETI_COMMAND+=" --config_file_path ${FORSETI_SERVER_CONF}"
FORSETI_COMMAND+=" --services ${FORSETI_SERVICES}"

SQL_PROXY_COMMAND="$(which cloud_sql_proxy)"
SQL_PROXY_COMMAND+=" -instances=${SQL_INSTANCE_CONN_STRING}=tcp:${SQL_PORT}"


# Cannot use "read -d" since it returns a nonzero exit status.
API_SERVICE="$(cat << EOF
[Unit]
Description=Forseti API Server
Wants=cloudsqlproxy.service
[Service]
User=ubuntu
Restart=always
RestartSec=3
ExecStart=$FORSETI_COMMAND
[Install]
WantedBy=multi-user.target
EOF
)"
echo "$API_SERVICE" > /tmp/forseti.service
sudo mv /tmp/forseti.service /lib/systemd/system/forseti.service

# By default, Systemd starts the executable stated in ExecStart= as root.
# See github issue #1761 for why this neds to be run as root.
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
