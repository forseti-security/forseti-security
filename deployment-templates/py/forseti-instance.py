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

"""Creates a Cloud SQL instance template for forseti_inventory."""


def GenerateConfig(context):
    """Generate configuration."""

    resources = []

    resources.append({
        'name': context.env['deployment'],
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
                    'value': """
#!/bin/bash
sudo apt-get install -y git unzip
sudo apt-get install -y python-pip python-dev

FORSETI_INVENTORY_PATH=`which forseti_inventory`

if [ -z "$FORSETI_INVENTORY_PATH" ]; then
        gsutil cp {}/forseti-security-master.zip /home/ubuntu
        cd /home/ubuntu
        unzip forseti-security-master.zip
        cd forseti-security-master
        python setup.py install
fi
""".format(context.properties['src-path'])
                }]
            }
        }
    })

    return {'resources': resources}
