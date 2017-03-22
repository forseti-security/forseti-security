#!/bin/bash
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

# A script to perform the download and installation of protobuf.

set -e

PROTOC_DOWNLOAD_PATH="/tmp/protoc"
FORSETI_PROTOC_URL="https://raw.githubusercontent.com/GoogleCloudPlatform/forseti-security/master/data/protoc_url.txt"

echo "Downloading protoc."
mkdir -p $PROTOC_DOWNLOAD_PATH
cd $PROTOC_DOWNLOAD_PATH
PROTOC_DOWNLOAD_URL=$(curl -s $FORSETI_PROTOC_URL)
wget -P $PROTOC_DOWNLOAD_PATH $PROTOC_DOWNLOAD_URL
unzip -d $PROTOC_DOWNLOAD_PATH $(basename $PROTOC_DOWNLOAD_URL)
