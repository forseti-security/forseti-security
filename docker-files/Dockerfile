# Copyright 2017 Google Inc.
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

# Dockerfile (experimental) for getting Forseti up and running.
# You still need to do all the other prereq GCP setup (e.g.
# setting up service accounts, GCP infrastructure).

FROM ubuntu:16.04

# Install Forseti dependencies
RUN apt-get update && apt-get install -qq -y \
    curl \
    git \
    libmysqlclient-dev \
    python-pip \
    python-dev \
    unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

ADD . /forseti-security/
WORKDIR /forseti-security/

RUN pip install -v --upgrade pip
RUN pip install -v --upgrade -r requirements.txt

RUN python setup.py install
RUN yes | which forseti_inventory
