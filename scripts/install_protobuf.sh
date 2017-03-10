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

PROTOBUF_VERSION="3.2.0"
wget https://github.com/google/protobuf/releases/download/v$PROTBUF_VERSION/protoc-$PROTOBUF_VERSION-linux-x86_64.zip
unzip protoc-$PROTBUF_VERSION-linux-x86_64.zip
cp protoc-$PROTBUF_VERSION-linux-x86_64/bin/protoc /usr/local/bin/protoc
