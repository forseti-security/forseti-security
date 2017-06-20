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

    SQL_INSTANCE = context.properties['sql-instance']
    EXPLAIN_DATABASE_NAME = context.properties['database-name-forseti']
    FORSETI_DATABASE_NAME = context.properties['database-name-explain']

    resources = []

    resources.append({
        'name': '{}-explain-vm'.format(context.env['deployment']),
        'type': 'compute.v1.instance',
        'properties': {
            'zone': context.properties['zone'],
            'machineType': (
                'https://www.googleapis.com/compute/v1/projects/{}'
                '/zones/{}/machineTypes/{}'.format(
                context.env['project'], context.properties['zone'],
                'n1-standard-2')),
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
        wget https://dl.google.com/cloudsql/cloud_sql_proxy.linux.amd64
        mv cloud_sql_proxy.linux.amd64 cloud_sql_proxy
        chmod +x cloud_sql_proxy
fi

# Install Forseti Security
cd $USER_HOME
rm -rf forseti-*
pip install --upgrade pip
pip install --upgrade setuptools
pip install google-apputils grpcio grpcio-tools protobuf

cd $USER_HOME

# Download Forseti src; see DOWNLOAD_FORSETI
{}
python setup.py install


# Create upstart script for API server
read -d '' API_SERVER << EOF
[Unit]
Description=Explain API Server
[Service]
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/forseti_api '[::]:50051' 'mysql://root@127.0.0.1:3306/{}' 'mysql://root@127.0.0.1:3306/{}' playground explain
[Install]
WantedBy=multi-user.target
Wants=cloudsqlproxy.service
EOF
echo "$API_SERVER" > /lib/systemd/system/forseti.service

read -d '' SQL_PROXY << EOF
[Unit]
Description=Explain Cloud SQL Proxy
[Service]
Restart=always
RestartSec=3
ExecStart=/home/ubuntu/cloud_sql_proxy -instances={}=tcp:3306
[Install]
WantedBy=forseti.service
EOF
echo "$SQL_PROXY" > /lib/systemd/system/cloudsqlproxy.service

systemctl start cloudsqlproxy
sleep 1
systemctl start forseti


""".format(

    # install forseti
    DOWNLOAD_FORSETI,
    EXPLAIN_DATABASE_NAME.split(':')[-1],
    FORSETI_DATABASE_NAME.split(':')[-1],

    # cloud_sql_proxy
    SQL_INSTANCE,
)
                }]
            }
        }
    })

    return {'resources': resources}
