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


def GenerateConfig(context):
    """Generate configuration."""

    BRANCH_NAME = context.properties.get('branch-name')
    FORSETI_HOME = '$USER_HOME/forseti-security'

    if BRANCH_NAME:
        DOWNLOAD_FORSETI = (
            "git clone {src_path}.git "
            "--branch {branch_name} "
            "--single-branch forseti-security").format(
            src_path=context.properties['src-path'],
            branch_name=context.properties['branch-name'])
    else:
        DOWNLOAD_FORSETI = (
            "wget -qO- {src_path}/archive/v{release_version}.tar.gz | tar xvz"
            "\nmv forseti-security-{release_version} forseti-security").format(
            src_path=context.properties['src-path'],
            release_version=context.properties['release-version'])

    FORSETI_CLIENT_CONF = ('gs://{bucket_name}/configs/'
                           'client/forseti_conf_client.yaml').format(
        bucket_name=context.properties['gcs-bucket'])
    SERVICE_ACCOUNT_SCOPES =  context.properties['service-account-scopes']
    PERSIST_FORSETI_VARS = (
        'export FORSETI_HOME={forseti_home}\n'
        'export FORSETI_CLIENT_CONFIG={forseti_client_conf}\n'
        ).format(forseti_home=FORSETI_HOME,
                 forseti_client_conf=FORSETI_CLIENT_CONF)

    resources = []

    deployment_name_splitted = context.env['deployment'].split('-')
    deployment_name_splitted.insert(len(deployment_name_splitted)-1, 'vm')
    instance_name = '-'.join(deployment_name_splitted)

    resources.append({
        'name':  instance_name,
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

# Ubuntu update.
sudo apt-get update -y
sudo apt-get upgrade -y

# Forseti setup.
sudo apt-get install -y git unzip

# Forseti dependencies
sudo apt-get install -y libffi-dev libssl-dev libmysqlclient-dev python-pip python-dev build-essential

USER=ubuntu
USER_HOME=/home/ubuntu

# Install fluentd if necessary.
FLUENTD=$(ls /usr/sbin/google-fluentd)
if [ -z "$FLUENTD" ]; then
      cd $USER_HOME
      curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
      bash install-logging-agent.sh
fi

# Install Forseti Security.
cd $USER_HOME
rm -rf *forseti*

# Download Forseti source code
{download_forseti}
cd forseti-security

# Forseti dependencies
pip install -q --upgrade setuptools pip wheel
pip install -q --upgrade -r requirements.txt

# Install Forseti
python setup.py install

# Set ownership of the forseti project to $USER
chown -R $USER {forseti_home}

# Export variables
{persist_forseti_vars}

# Store the variables in /etc/profile.d/forseti_environment.sh 
# so all the users will have access to them
echo "echo '{persist_forseti_vars}' >> /etc/profile.d/forseti_environment.sh" | sudo sh

echo "Execution of startup script finished"
""".format(
                        # Install Forseti.
                        download_forseti=DOWNLOAD_FORSETI,

                        # Set ownership for Forseti conf and rules dirs
                        forseti_home=FORSETI_HOME,

                        # Env variables for Forseti
                        persist_forseti_vars=PERSIST_FORSETI_VARS,
                    )
                }]
            }
        }
    })
    return {'resources': resources}
