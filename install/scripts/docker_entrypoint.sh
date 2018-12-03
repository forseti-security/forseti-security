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
gsutil cp ${BUCKET}/configs/forseti_conf_server.yaml /forseti-security/configs/forseti_conf_server.yaml
gsutil cp -r ${BUCKET}/rules /forseti-security/

# TODO Error handling for gsutil cp

# Start Forseti server
# This requires the cloud sql proxy (side car) container is running on 127.0.0.1:3306
forseti_server \
--endpoint "localhost:50051" \
--forseti_db "mysql://root@127.0.0.1:3306/forseti_security" \
--services scanner model inventory explain notifier \
--config_file_path "/forseti-security/configs/forseti_conf_server.yaml" \
--log_level=info \
--enable_console_log