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

"""Creates a GCE instance template for Forseti Security."""

SQL_PORT = '3306'

def GenerateConfig(context):
    """Generate configuration."""

    if context.properties.get('branch-name'):
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

    SQL_INSTANCE_CONN_STRING = '{}:{}:{}'.format(
        context.env['project'],
        '$(ref.cloudsql-instance.region)',
        '$(ref.cloudsql-instance.name)')

    FORSETI_DB_NAME = context.properties['forseti-db-name']
    GSUITE_SERVICE_ACCOUNT_PATH = context.properties['gsuite-service-accout-path']
    GSUITE_ADMIN_EMAIL = context.properties['gsuite-admin-email']
    ROOT_RESOURCE_ID = context.properties['root-resource-id']

    resources = []

    EXPORT_INITIALIZE_VARS = (
        'export SQL_PORT={0}\n'
        'export SQL_INSTANCE_CONN_STRING="{1}"\n'
        'export FORSETI_DB_NAME="{2}"\n'
        'export GSUITE_ADMIN_EMAIL="{3}"\n'
        'export GSUITE_ADMIN_CREDENTIAL_PATH="{4}"\n'
        'export ROOT_RESOURCE_ID="{5}"\n')
    EXPORT_INITIALIZE_VARS = EXPORT_INITIALIZE_VARS.format(
        SQL_PORT, SQL_INSTANCE_CONN_STRING, FORSETI_DB_NAME,
        GSUITE_ADMIN_EMAIL, GSUITE_SERVICE_ACCOUNT_PATH, ROOT_RESOURCE_ID)


    resources.append({
        'name': '{}-explain-vm'.format(context.env['deployment']),
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
                            'ubuntu-os-cloud',
                            'ubuntu-1604-lts',
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
                'scopes': ['https://www.googleapis.com/auth/cloud-platform'],
            }],
            'metadata': {
                'dependsOn': ['db-instances'],
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
sudo apt-get install -y libmysqlclient-dev python-pip python-dev libssl-dev build-essential libffi-dev
USER_HOME=/home/ubuntu

# Install fluentd if necessary
FLUENTD=$(ls /usr/sbin/google-fluentd)
if [ -z "$FLUENTD" ]; then
    cd $USER_HOME
    curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
    bash install-logging-agent.sh
fi

# Check whether Cloud SQL proxy is installed
if ! [[ -x /usr/bin/cloud_sql_proxy ]]; then
    cd $USER_HOME
    wget https://dl.google.com/cloudsql/cloud_sql_proxy.linux.amd64 \
            -O /tmp/cloud_sql_proxy
    chmod 755 /tmp/cloud_sql_proxy
    sudo mv /tmp/cloud_sql_proxy /usr/bin/cloud_sql_proxy
fi

# Install Forseti Security
cd $USER_HOME
rm -rf forseti-*
pip install --upgrade pip
pip install --upgrade setuptools
pip install google-apputils grpcio grpcio-tools protobuf

cd $USER_HOME

# Download Forseti src; see DOWNLOAD_FORSETI
{download_forseti_bash}
python setup.py install

# Export variables required by initialize_explain_services.sh.
{export_initialize_vars}

# Start explain service depends on vars defined above.
bash ./scripts/gcp_setup/bash_scripts/initialize_explain_services.sh

echo "Starting services."
systemctl start cloudsqlproxy
sleep 5
systemctl start forseti
echo "Success! The Forseti API server has been started."


""".format(download_forseti_bash=DOWNLOAD_FORSETI,
           export_initialize_vars=EXPORT_INITIALIZE_VARS)
                }]
            }
        }
    })
    return {'resources': resources}
