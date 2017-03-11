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

if [ ! -d /tmp/protoc/bin ]; then
  mkdir -p $PROTOC_DOWNLOAD_PATH
  cd $PROTOC_DOWNLOAD_PATH
  wget https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip
  unzip protoc-3.2.0-linux-x86_64.zip
else
  echo "Using cached protoc directory."
fi

echo "Installing protoc."
sudo cp /tmp/protoc/bin/protoc $PROTOC_PATH
sudo chmod 755 $PROTOC
