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

# Put the config files in place.
gsutil cp gs://$SCANNER_BUCKET/configs/forseti_conf.yaml $FORSETI_CONF
gsutil cp -r gs://$SCANNER_BUCKET/rules $FORSETI_HOME/

if [ ! -f "$FORSETI_CONF" ]; then
    echo Forseti conf not found, exiting.
    exit 1
fi

# inventory command
/usr/local/bin/forseti_inventory --forseti_config $FORSETI_CONF

# scanner command
/usr/local/bin/forseti_scanner --forseti_config $FORSETI_CONF

# notifier command
/usr/local/bin/forseti_notifier --forseti_config $FORSETI_CONF
