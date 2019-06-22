# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

##### BEGIN BASE IMAGE #####
FROM python:3.6-slim as base

ENV HOME=/home/forseti \
    WORK_DIR=/home/forseti/forseti-security \
    PATH=/home/forseti/.local/bin:$PATH

RUN groupadd -g 1000 forseti && \
    useradd -d ${HOME} -u 1000 -g forseti forseti && \
    mkdir -p ${HOME}/forseti-security && \
    chown -R forseti:forseti ${HOME}

# Install host dependencies.
RUN apt-get update  && \
    apt-get install --no-install-recommends -y libmariadbclient18 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR ${WORK_DIR}

USER forseti
##### END BASE IMAGE #####

##### BEGIN PRE-BUILD IMAGE #####
FROM base AS pre-build

USER root
# Install Forseti Security dependencies.
# This should stay in sync with the deployment script used on the host machine in
#   deployment-templates/compute-engine/forseti-instance.py
RUN apt-get update  && \
    apt-get install -y build-essential \
                       libffi-dev \
                       libssl-dev \
                       libgmp-dev \
                       default-libmysqlclient-dev

USER forseti
##### END PRE-BUILD IMAGE #####

##### BEGIN BUILD IMAGE #####
FROM pre-build AS build

# Expose our source so we can install Forseti Security.
COPY --chown=forseti:forseti . ${WORK_DIR}

RUN pip install --no-cache-dir --upgrade -r requirements.txt --user

# Install Forseti Security.
RUN python setup.py install --user

##### END BUILD IMAGE #####

##### BEGIN RUNTIME IMAGE #####
FROM base AS runtime

USER forseti

COPY --from=build --chown=forseti:forseti \
    /home/forseti/.local \
    /home/forseti/.local

COPY --from=build --chown=forseti:forseti \
    /home/forseti/forseti-security/.eggs/ \
    /home/forseti/.local/lib/python3.6/site-packages/

COPY --from=build --chown=forseti:forseti \
    /home/forseti/forseti-security/install/scripts/docker_entrypoint.sh \
    /home/forseti/.local/bin/

RUN chmod u+x /home/forseti/.local/bin/docker_entrypoint.sh

ENTRYPOINT ["docker_entrypoint.sh"]
