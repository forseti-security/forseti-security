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

    FORSETI_HOME = '$USER_HOME/forseti-security'

    DOWNLOAD_FORSETI = (
        "git clone {src_path}.git".format(
            src_path=context.properties['src-path']))

    FORSETI_VERSION = (
        "git checkout {forseti_version}".format(
            forseti_version=context.properties['forseti-version']))

    CLOUDSQL_CONN_STRING = '{}:{}:{}'.format(
        context.env['project'],
        '$(ref.cloudsql-instance.region)',
        '$(ref.cloudsql-instance.name)')

    SCANNER_BUCKET = context.properties['scanner-bucket']
    FORSETI_DB_NAME = context.properties['database-name']
    SERVICE_ACCOUNT_SCOPES =  context.properties['service-account-scopes']
    FORSETI_SERVER_CONF = '{}/configs/forseti_conf_server.yaml'.format(FORSETI_HOME)

    EXPORT_INITIALIZE_VARS = (
        'export SQL_PORT={0}\n'
        'export SQL_INSTANCE_CONN_STRING="{1}"\n'
        'export FORSETI_DB_NAME="{2}"\n')
    EXPORT_INITIALIZE_VARS = EXPORT_INITIALIZE_VARS.format(
        context.properties['db-port'],
        CLOUDSQL_CONN_STRING,
        FORSETI_DB_NAME)

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

# Install Google Cloud SDK
sudo apt-get --assume-yes install google-cloud-sdk

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
git fetch --all
{checkout_forseti_version}

# Forseti Host Setup
sudo apt-get install -y git unzip

# Forseti host dependencies
sudo apt-get install -y $(cat install/dependencies/apt_packages.txt | grep -v "#" | xargs)

# Forseti dependencies
pip install --upgrade pip==9.0.3
pip install -q --upgrade setuptools wheel
pip install -q --upgrade -r requirements.txt

# Setup Forseti logging
touch /var/log/forseti.log
chown ubuntu:root /var/log/forseti.log
cp {forseti_home}/configs/logging/fluentd/forseti.conf /etc/google-fluentd/config.d/forseti.conf
cp {forseti_home}/configs/logging/logrotate/forseti /etc/logrotate.d/forseti
chmod 644 /etc/logrotate.d/forseti
service google-fluentd restart
logrotate /etc/logrotate.conf

# Change the access level of configs/ rules/ and run_forseti.sh
chmod -R ug+rwx {forseti_home}/configs {forseti_home}/rules {forseti_home}/install/gcp/scripts/run_forseti.sh

# Install Forseti
python setup.py install

# Export variables required by initialize_forseti_services.sh.
{export_initialize_vars}

# Export variables required by run_forseti.sh
{export_forseti_vars}

# Store the variables in /etc/profile.d/forseti_environment.sh 
# so all the users will have access to them
echo "echo '{export_forseti_vars}' >> /etc/profile.d/forseti_environment.sh" | sudo sh

# Download server configuration from GCS
gsutil cp gs://{scanner_bucket}/configs/forseti_conf_server.yaml {forseti_server_conf}
gsutil cp -r gs://{scanner_bucket}/rules {forseti_home}/

# Start Forseti service depends on vars defined above.
bash ./install/gcp/scripts/initialize_forseti_services.sh

echo "Starting services."
systemctl start cloudsqlproxy
sleep 5

echo "Attempting to update database schema, if necessary."
python $USER_HOME/forseti-security/install/gcp/upgrade_tools/db_migrator.py

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

# Use flock to prevent rerun of the same cron job when the previous job is still running.
# If the lock file does not exist under the tmp directory, it will create the file and put a lock on top of the file.
# When the previous cron job is not finished and the new one is trying to run, it will attempt to acquire the lock
# to the lock file and fail because the file is already locked by the previous process.
# The -n flag in flock will fail the process right away when the process is not able to acquire the lock so we won't
# queue up the jobs.
# If the cron job failed the acquire lock on the process, it will log a warning message to syslog.

(echo "{run_frequency} (/usr/bin/flock -n /home/ubuntu/forseti-security/forseti_cron_runner.lock $FORSETI_HOME/install/gcp/scripts/run_forseti.sh || echo '[forseti-security] Warning: New Forseti cron job will not be started, because previous Forseti job is still running.') 2>&1 | logger") | crontab -u $USER -
echo "Added the run_forseti.sh to crontab under user $USER"

echo "Execution of startup script finished"
""".format(
    # Cloud SQL properties
    cloudsql_arch = context.properties['cloudsqlproxy-os-arch'],

    # Install Forseti.
    download_forseti=DOWNLOAD_FORSETI,

    # Checkout Forseti version.
    checkout_forseti_version=FORSETI_VERSION,

    # Set ownership for Forseti conf and rules dirs
    forseti_home=FORSETI_HOME,

    # Download the Forseti conf and rules.
    scanner_bucket=SCANNER_BUCKET,
    forseti_server_conf=FORSETI_SERVER_CONF,

    # Env variables for Explain
    export_initialize_vars=EXPORT_INITIALIZE_VARS,

    # Env variables for Forseti
    export_forseti_vars=EXPORT_FORSETI_VARS,

    # Forseti run frequency
    run_frequency=RUN_FREQUENCY,
)
                }]
            }
        }
    })
    return {'resources': resources}
