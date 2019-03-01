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

# Forseti Server Docker startup on Container Optimized OS (cos)
# for Proof of Concept Purposes
# Assumes script is running on cos running with Forseti Service Account

# Pull Cloud SQL Proxy Docker Image
docker pull gcr.io/cloudsql-docker/gce-proxy:1.12

# TODO Set connection
CLOUD_SQL_CONNECTION_NAME="<project>:<region>:<db>"

# Run Cloud SQL Proxy
sudo docker run -d -v /mnt/stateful_partition/cloudsql:/cloudsql \
  -p 127.0.0.1:3306:3306 \
  gcr.io/cloudsql-docker/gce-proxy:1.12 /cloud_sql_proxy \
  -instances=${CLOUD_SQL_CONNECTION_NAME}=tcp:0.0.0.0:3306


# TODO pull and run the forseti image? For now we assume it was deployed via cloud console and is already running
# on the cos
# TODO set variables
CONTAINER_ID=<>
BUCKET=gs://<>

# Run Forseti server
sudo docker exec ${CONTAINER_ID} /forseti-security/install/scripts/docker_entrypoint.sh --bucket ${BUCKET}

# Test commands for Forseti server
# Attach to container and run test commands as normal or run from outside container via exec
# TODO how to return to cmd prompt after running exec without having to 'ctrl c' each time?
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti inventory list'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti model list'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti inventory purge 0'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti model delete model_adhoc'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti inventory create --import_as model_adhoc'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti model use model_adhoc'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti scanner run'
#sudo docker exec ${CONTAINER_ID} sh -c 'forseti notifier run'
