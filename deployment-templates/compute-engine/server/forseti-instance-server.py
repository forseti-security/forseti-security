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

import random

def GenerateConfig(context):
    """Generate configuration."""

    USE_BRANCH = context.properties.get('branch-name')
    FORSETI_HOME = '$USER_HOME/forseti-security'

    if USE_BRANCH:
        DOWNLOAD_FORSETI = """
git clone {src_path}.git --branch {branch_name} --single-branch forseti-security
        """.format(
            src_path=context.properties['src-path'],
            branch_name=context.properties['branch-name'])
    else:
        DOWNLOAD_FORSETI = """
wget -qO- {src_path}/archive/v{release_version}.tar.gz | tar xvz
mv forseti-security-{release_version} forseti-security
        """.format(
            src_path=context.properties['src-path'],
            release_version=context.properties['release-version'])

    CLOUDSQL_CONN_STRING = '{}:{}:{}'.format(
        context.env['project'],
        '$(ref.cloudsql-instance.region)',
        '$(ref.cloudsql-instance.name)')

    SCANNER_BUCKET = context.properties['scanner-bucket']
    FORSETI_DB_NAME = context.properties['database-name']
    SERVICE_ACCOUNT_SCOPES =  context.properties['service-account-scopes']
    FORSETI_SERVER_CONF = '{}/configs/forseti_conf_server.yaml'.format(FORSETI_HOME)

    GSUITE_ADMIN_CREDENTIAL_PATH = '/home/ubuntu/gsuite_key.json'

    EXPORT_INITIALIZE_VARS = (
        'export SQL_PORT={0}\n'
        'export SQL_INSTANCE_CONN_STRING="{1}"\n'
        'export FORSETI_DB_NAME="{2}"\n'
        'export GSUITE_ADMIN_CREDENTIAL_PATH="{3}"\n')
    EXPORT_INITIALIZE_VARS = EXPORT_INITIALIZE_VARS.format(
        context.properties['db-port'],
        CLOUDSQL_CONN_STRING,
        FORSETI_DB_NAME,
        GSUITE_ADMIN_CREDENTIAL_PATH)

    EXPORT_FORSETI_VARS = (
        'export FORSETI_HOME={forseti_home}\n'
        'export FORSETI_SERVER_CONF={forseti_server_conf}\n'
        ).format(forseti_home=FORSETI_HOME,
                 forseti_server_conf=FORSETI_SERVER_CONF)

    RUN_FREQUENCY = context.properties['run-frequency']

    resources = []

    deployment_name_splitted = context.env['deployment'].split('-')
    deployment_name_splitted.insert(len(deployment_name_splitted)-1, 'vm')
    instance_name = '-'.join(deployment_name_splitted)

    resources.append({
        'name': instance_name,
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

USER_HOME=/home/ubuntu

# Install fluentd if necessary.
FLUENTD=$(ls /usr/sbin/google-fluentd)
if [ -z "$FLUENTD" ]; then
      cd $USER_HOME
      curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
      bash install-logging-agent.sh
fi

# Check whether Cloud SQL proxy is installed.
CLOUD_SQL_PROXY=$(which cloud_sql_proxy)
if [ -z "$CLOUD_SQL_PROXY" ]; then
        cd $USER_HOME
        wget https://dl.google.com/cloudsql/cloud_sql_proxy.{cloudsql_arch}
        sudo mv cloud_sql_proxy.{cloudsql_arch} /usr/local/bin/cloud_sql_proxy
        chmod +x /usr/local/bin/cloud_sql_proxy
fi

# Install Forseti Security.
cd $USER_HOME
rm -rf *forseti*

# Download Forseti source code
{download_forseti}
cd forseti-security

# Forseti Host Setup
sudo apt-get install -y git unzip

# Forseti host dependencies
sudo apt-get install -y $(cat setup/dependencies/apt_packages.txt | grep -v "#" | xargs)

# Forseti dependencies
pip install --upgrade pip==9.0.3
pip install -q --upgrade setuptools wheel
pip install -q --upgrade -r requirements.txt

# Change the access level of configs/ rules/ and run_forseti.sh
chmod -R ug+rwx {forseti_home}/configs {forseti_home}/rules {forseti_home}/setup/gcp/scripts/run_forseti.sh

# Install Forseti
python setup.py install

# Export variables required by initialize_forseti_services.sh.
{export_initialize_vars}

# Export variables required by run_forseti.sh
{export_forseti_vars}

# Store the variables in /etc/profile.d/forseti_environment.sh 
# so all the users will have access to them
echo "echo '{export_forseti_vars}' >> /etc/profile.d/forseti_environment.sh" | sudo sh


# Rotate gsuite key
# TODO: consider moving this to the forseti_server
python $FORSETI_HOME/setup/gcp/util/rotate_gsuite_key.py {gsuite_service_acct} $GSUITE_ADMIN_CREDENTIAL_PATH
chown ubuntu:root $GSUITE_ADMIN_CREDENTIAL_PATH

# Download server configuration from GCS
gsutil cp gs://{scanner_bucket}/configs/forseti_conf_server.yaml {forseti_server_conf}
gsutil cp -r gs://{scanner_bucket}/rules {forseti_home}/

# Start Forseti service depends on vars defined above.
bash ./setup/gcp/scripts/initialize_forseti_services.sh

echo "Starting services."
systemctl start cloudsqlproxy
sleep 5
systemctl start forseti
echo "Success! The Forseti API server has been started."

# Create a Forseti env script
FORSETI_ENV="$(cat <<EOF
#!/bin/bash

export PATH=$PATH:/usr/local/bin

# Forseti environment variables
export FORSETI_HOME=/home/ubuntu/forseti-security
export FORSETI_SERVER_CONF=$FORSETI_HOME/configs/forseti_conf_server.yaml
export SCANNER_BUCKET={scanner_bucket}
EOF
)"
echo "$FORSETI_ENV" > $USER_HOME/forseti_env.sh

USER=ubuntu
(echo "{run_frequency} $FORSETI_HOME/setup/gcp/scripts/run_forseti.sh") | crontab -u $USER -
echo "Added the run_forseti.sh to crontab under user $USER"

echo "Execution of startup script finished"
""".format(
    # Cloud SQL properties
    cloudsql_arch = context.properties['cloudsqlproxy-os-arch'],

    # Install Forseti.
    download_forseti=DOWNLOAD_FORSETI,

    # Set ownership for Forseti conf and rules dirs
    forseti_home=FORSETI_HOME,

    # Download the Forseti conf and rules.
    scanner_bucket=SCANNER_BUCKET,
    forseti_server_conf=FORSETI_SERVER_CONF,

    # Env variables for Explain
    export_initialize_vars=EXPORT_INITIALIZE_VARS,

    # Env variables for Forseti
    export_forseti_vars=EXPORT_FORSETI_VARS,

    gsuite_service_acct=context.properties['service-account-gsuite'],

    # Forseti run frequency
    run_frequency=RUN_FREQUENCY,
)
                }]
            }
        }
    })
    return {'resources': resources}
