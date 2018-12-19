#!/bin/bash

# Forseti Server Docker startup on Container Optimized OS (cos)
# for Proof of Concept Purposes
# Assumes cos running with Forseti Service Account

# Pull Cloud SQL Proxy Docker Image
docker pull gcr.io/cloudsql-docker/gce-proxy:1.12

# TODO Set connection
CLOUD_SQL_CONNECTION_NAME="<project>:<region>:<db>"

# Run Cloud SQL Proxy
sudo docker run -d -v /mnt/stateful_partition/cloudsql:/cloudsql \
  -p 127.0.0.1:3306:3306 \
  gcr.io/cloudsql-docker/gce-proxy:1.12 /cloud_sql_proxy \
  -instances=${CLOUD_SQL_CONNECTION_NAME}=tcp:0.0.0.0:3306

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
