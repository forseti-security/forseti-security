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


def get_patch_search_expression(forseti_version):
    """Returns a glob expression matching all patches of the given version.

    TODO: Update in server/forseti-instance-server if update here.

    Args:
        forseti_version (str): Installed forseti version.  Should start with
            'tags/v' if patches are to be updated automatically.

    Returns:
        str: Glob expression matching all patches of given forseti_version.
        None: Returns None if forseti_version is not in 'tags/vX.Y.Z' format.
    """

    if forseti_version[:6] != 'tags/v':
        return None

    segments = forseti_version.replace('tags/v', '').split('.')
    for segment in segments:
        if not segment.isdigit():
            return None

    return 'v{}.{}.{{[0-9],[0-9][0-9]}}'.format(segments[0], segments[1])


def GenerateConfig(context):
    """Generate configuration."""

    FORSETI_HOME = '$USER_HOME/forseti-security'

    DOWNLOAD_FORSETI = (
        "git clone {src_path}.git".format(
            src_path=context.properties['src-path']))

    patch_search_expression = get_patch_search_expression(context.properties['forseti-version'])
    if patch_search_expression:
        CHECKOUT_FORSETI_VERSION = (
            """versions=$(git tag -l {patch_search_expression})
versions=(${{versions//;/ }})
for version in "${{versions[@]}}"
do
segments=(${{version//./ }})
patch=${{segments[2]}}
patch=${{patch: 0: 2}}
patch=$(echo $patch | sed 's/[^0-9]*//g')
# latest_version is an array [full_version, patch_number]
if !((${{#latest_version[@]}})) || ((patch > ${{latest_version[1]}}));
then
  latest_version=($version $patch)
fi
done
git checkout ${{latest_version[0]}}"""
                .format(patch_search_expression=patch_search_expression))
    else:
        CHECKOUT_FORSETI_VERSION = (
            "git checkout {forseti_version}".format(
                forseti_version=context.properties['forseti-version']))

    FORSETI_CLIENT_CONF = ('gs://{bucket_name}/configs/'
                           'forseti_conf_client.yaml').format(
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
                    'projects/{}/global/networks/{}'.format(
                    context.properties['vpc-host-project-id'],
                    context.properties['vpc-host-network'])),
                'accessConfigs': [{
                    'name': 'External NAT',
                    'type': 'ONE_TO_ONE_NAT'
                }],
                'subnetwork': (
                    'https://www.googleapis.com/compute/v1/'
                    'projects/{}/regions/{}/subnetworks/{}'.format(
                        context.properties['vpc-host-project-id'],
                        context.properties['region'],
                        context.properties['vpc-host-subnetwork']))
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

# Ubuntu available packages refresh.
sudo apt-get update -y

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
# Fetch tags updates tag changes which fetch all doesn't do
git fetch --tags
git fetch --all
{checkout_forseti_version}

# Forseti dependencies
pip install --upgrade pip==9.0.3
pip install -q --upgrade setuptools wheel
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

                        # If installed on a version tag, checkout latest patch.
                        # Otherwise checkout originally installed version.
                        checkout_forseti_version=CHECKOUT_FORSETI_VERSION,

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
