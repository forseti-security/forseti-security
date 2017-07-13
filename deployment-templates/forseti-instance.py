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

    USE_BRANCH = context.properties.get('branch-name')
    ORGANIZATION_ID = context.properties['organization-id']

    if USE_BRANCH:
        DOWNLOAD_FORSETI = """
git clone {}.git --branch {} --single-branch forseti-security
cd forseti-security
        """.format(
            context.properties['src-path'],
            context.properties['branch-name'])
    else:
        DOWNLOAD_FORSETI = """
wget -qO- {}/archive/v{}.tar.gz | tar xvz
cd forseti-security-{}
        """.format(
            context.properties['src-path'],
            context.properties['release-version'],
            context.properties['release-version'])

    CLOUDSQL_CONN_STRING = '{}:{}:{}'.format(
        context.env['project'],
        '$(ref.cloudsql-instance.region)',
        '$(ref.cloudsql-instance.name)')

    SCANNER_BUCKET = context.properties['scanner-bucket']
    SERVICE_ACCOUNT_SCOPES =  context.properties['service-account-scopes']
    FORSETI_CONFIG = context.properties['forseti-config']

    inventory_command = (
        '/usr/local/bin/forseti_inventory --forseti_config {} '
            .format(
                FORSETI_CONFIG,
            )
    )

    scanner_command = (
        ('/usr/local/bin/forseti_scanner --forseti_config {} ')
            .format(
                FORSETI_CONFIG,
            )
    )

    NEW_BUILD_PROTOS = """
# Build protos separately.
python build_protos.py --clean
"""

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
                            context.properties['image-family']
                        )
                    )
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
                'scopes': SERVICE_ACCOUNT_SCOPES,
            }],
            'metadata': {
                'items': [{
                    'key': 'startup-script',
                    'value': """#!/bin/bash
exec > /tmp/deployment.log
exec 2>&1

# Ubuntu update
sudo apt-get update -y
sudo apt-get upgrade -y

# Forseti setup
sudo apt-get install -y git unzip
# Forseti dependencies
sudo apt-get install -y libmysqlclient-dev python-pip python-dev

USER_HOME=/home/ubuntu

# Install fluentd if necessary
FLUENTD=$(ls /usr/sbin/google-fluentd)
if [ -z "$FLUENTD" ]; then
      cd $USER_HOME
      curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
      bash install-logging-agent.sh
fi

# Check whether Cloud SQL proxy is installed
CLOUD_SQL_PROXY=$(ls $USER_HOME/cloud_sql_proxy)
if [ -z "$CLOUD_SQL_PROXY" ]; then
        cd $USER_HOME
        wget https://dl.google.com/cloudsql/cloud_sql_proxy.{}
        mv cloud_sql_proxy.{} cloud_sql_proxy
        chmod +x cloud_sql_proxy
fi

$USER_HOME/cloud_sql_proxy -instances={}=tcp:{} &

# Install Forseti Security
cd $USER_HOME
rm -rf forseti-*
rm -rf run_forseti.sh
pip install --upgrade pip
pip install --upgrade setuptools
pip install grpcio grpcio-tools google-apputils

# Download Forseti src; see DOWNLOAD_FORSETI
{}

# Build protos
{}

python setup.py install

# Create the startup run script
read -d '' RUN_FORSETI << EOF
#!/bin/bash

if [ ! -f {} ]; then
    echo Forseti conf not found, exiting.
    exit 1
fi

# inventory command
{}
# scanner command
{}

EOF
echo "$RUN_FORSETI" > $USER_HOME/run_forseti.sh
chmod +x $USER_HOME/run_forseti.sh
/bin/sh $USER_HOME/run_forseti.sh

(echo "0 * * * * $USER_HOME/run_forseti.sh") | crontab -
""".format(
    # cloud_sql_proxy
    context.properties['cloudsqlproxy-os-arch'],
    context.properties['cloudsqlproxy-os-arch'],
    CLOUDSQL_CONN_STRING,
    context.properties['db-port'],

    # install forseti
    DOWNLOAD_FORSETI,

    # new style build protos
    NEW_BUILD_PROTOS,

    # run_forseti.sh
    FORSETI_CONFIG,

    # - forseti_inventory
    inventory_command,

    # - forseti_scanner
    scanner_command,
)
                }]
            }
        }
    })
    return {'resources': resources}
