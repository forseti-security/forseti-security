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

"""Creates a GCE instance template for Forseti Security."""


def GenerateConfig(context):
    """Generate configuration."""

    CLOUDSQL_CONN_STRING = '{}:{}:{}'.format(context.env['project'],
        '$(ref.cloudsql-instance.region)',
        '$(ref.cloudsql-instance.name)')
    SCANNER_BUCKET = '$(ref.scanner-bucket.name)'

    resources = []

    resources.append({
        'name': '{}-vm'.format(context.env['deployment']),
        'type': 'compute.v1.instance',
        'properties': {
            'zone': context.properties['zone'],
            'machineType': (
                'https://www.googleapis.com/compute/v1/projects/{}'
                '/zones/{}/machineTypes/{}'.format(
                context.env['project'], context.properties['zone'], 
                context.properties['instance-type'])),
            'disks': [{
                'deviceName': 'boot',
                'type': 'PERSISTENT',
                'boot': True,
                'autoDelete': True,
                'initializeParams': {
                    'sourceImage': (
                        'https://www.googleapis.com/compute/v1'
                        '/projects/{}/global/images/family/{}'.format(
                        context.properties['image-project'],
                        context.properties['image-family']))
                }
            }],
            'networkInterfaces': [{
                'network': (
                    'https://www.googleapis.com/compute/v1/'
                    'projects/{}/global/networks/default'.format(
                    context.env['project'])),
                'accessConfigs': [{
                    'name': 'External NAT',
                    'type': 'ONE_TO_ONE_NAT'
                }]
            }],
            'serviceAccounts': [{
                'email': context.properties['service-account'],
                'scopes': ['https://www.googleapis.com/auth/cloud-platform']
            }],
            'metadata': {
                'items': [{
                    'key': 'startup-script',
                    'value': """#!/bin/bash
sudo apt-get install -y git unzip git
sudo apt-get install -y libmysqlclient-dev
sudo apt-get install -y python-pip python-dev virtualenvwrapper

USER_HOME=/home/ubuntu

# Check whether Cloud SQL proxy is installed
CLOUD_SQL_PROXY=$(ls $USER_HOME/cloud_sql_proxy)
if [ -z "$CLOUD_SQL_PROXY" ]; then
        cd $USER_HOME
        wget https://dl.google.com/cloudsql/cloud_sql_proxy.{}
        mv cloud_sql_proxy.{} cloud_sql_proxy
        chmod +x cloud_sql_proxy
fi

$USER_HOME/cloud_sql_proxy -instances={}=tcp:{} &

# Check if rules.yaml exists
RULES_FILE=$(gsutil ls gs://{}/rules/rules.yaml)
if [ $? -eq 1 ]; then
        cd $USER_HOME
        read -d '' RULES_YAML << EOF
rules:
  - name: sample whitelist
    mode: whitelist
    resource:
      - type: organization
        applies_to: self_and_children
        resource_ids:
          - {}
    inherit_from_parents: true
    bindings:
      - role: roles/*
        members:
          - serviceAccount:*@*.gserviceaccount.com
EOF
        echo "$RULES_YAML" > $USER_HOME/rules.yaml
        gsutil cp $USER_HOME/rules.yaml gs://{}/rules/rules.yaml
fi

# Check whether protoc is installed
PROTOC_PATH=$(which protoc)
if [ -z "$PROTOC_PATH" ]; then
        cd $USER_HOME
        wget https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip
        unzip -o protoc-3.2.0-linux-x86_64.zip
        sudo cp bin/protoc /usr/local/bin
fi

# Check whether Forseti Security is installed
FORSETI_INVENTORY_PATH=$(which forseti_inventory)
if [ -z "$FORSETI_INVENTORY_PATH" ]; then
        cd $USER_HOME
        rm -rf forseti-*
        virtualenv forseti-env
        source forseti-env/bin/activate
        pip install --upgrade pip
        pip install --upgrade setuptools

        cd $USER_HOME
        gsutil cp {}/forseti-security-master.zip .
        unzip -o forseti-security-master.zip
        cd forseti-security-master
        python setup.py install

        read -d '' RUN_FORSETI << EOF
#!/bin/bash
forseti_inventory --organization_id {} --db_name {}
forseti_scanner --rules {} --db_name {} --output_path {}
EOF
        echo "$RUN_FORSETI" > $USER_HOME/run_forseti.sh
        chmod +x $USER_HOME/run_forseti.sh
fi

source $USER_HOME/forseti-env/bin/activate
$USER_HOME/run_forseti.sh
""".format(
           # cloud_sql_proxy
           context.properties['cloudsqlproxy-os-arch'],
           context.properties['cloudsqlproxy-os-arch'],
           CLOUDSQL_CONN_STRING,
           context.properties['db-port'],

           # rules.yaml
           SCANNER_BUCKET,
           context.properties['organization-id'],
           SCANNER_BUCKET,

           # download forseti src code
           context.properties['src-path'],

           # run_forseti.sh
           # - forseti_inventory
           context.properties['organization-id'],
           '$(ref.cloudsql-database.name)',
           # - forseti_scanner
           'gs://{}/rules/rules.yaml'.format(SCANNER_BUCKET),
           '$(ref.cloudsql-database.name)',
           'gs://{}/scanner_violations'.format(SCANNER_BUCKET),
)
                }]
            }
        }
    })

    return {'resources': resources}
