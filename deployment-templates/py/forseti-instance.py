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

    RELEASE_VERSION = context.properties['release-version']

    CLOUDSQL_CONN_STRING = '{}:{}:{}'.format(context.env['project'],
        '$(ref.cloudsql-instance.region)',
        '$(ref.cloudsql-instance.name)')
    SCANNER_BUCKET = context.properties['scanner-bucket']
    DATABASE_NAME = context.properties['database-name']
    SHOULD_INVENTORY_GROUPS = bool(context.properties['inventory-groups'])

    SERVICE_ACCOUNT_SCOPES =  context.properties['service-account-scopes']

    inventory_command = '/usr/local/bin/forseti_inventory --organization_id {} --db_name {} '.format(
        context.properties['organization-id'],
        DATABASE_NAME,
    )

    scanner_command = '/usr/local/bin/forseti_scanner --rules {} --output_path {} --organization_id {} --db_name {} '.format(
        'gs://{}/rules/rules.yaml'.format(SCANNER_BUCKET),
        'gs://{}/scanner_violations'.format(SCANNER_BUCKET),
        context.properties['organization-id'],
        DATABASE_NAME,
    )

    # Extend the commands, based on whether email is required.
    SENDGRID_API_KEY = context.properties.get('sendgrid-api-key')
    EMAIL_SENDER = context.properties.get('email-sender')
    EMAIL_RECIPIENT = context.properties.get('email-recipient')
    if EMAIL_RECIPIENT is not None:
        email_flags = '--sendgrid_api_key {} --email_sender {} --email_recipient {}'.format(
            SENDGRID_API_KEY,
            EMAIL_SENDER,
            EMAIL_RECIPIENT,
        )
        inventory_command = inventory_command + email_flags
        scanner_command = scanner_command + email_flags

    # Extend the commands, based on whether inventory-groups is set.
    if SHOULD_INVENTORY_GROUPS:
        GROUPS_DOMAIN_SUPER_ADMIN_EMAIL = context.properties['groups-domain-super-admin-email']
        GROUPS_SERVICE_ACCOUNT_EMAIL = context.properties['groups-service-account-email']
        GROUPS_SERVICE_ACCOUNT_CREDENTIALS_METADATA_SERVER_KEY = context.properties[
            'groups-service-account-credentials-metadata-server-key']

        inventory_groups_flags = '--domain_super_admin_email {} --groups_service_accounts_email {} --groups_service_account_credentials_metadata_server_key {}'.format(
            GROUPS_DOMAIN_SUPER_ADMIN_EMAIL,
            GROUPS_SERVICE_ACCOUNT_EMAIL,
            GROUPS_SERVICE_ACCOUNT_CREDENTIALS_METADATA_SERVER_KEY,
        )
        inventory_command = inventory_command + inventory_groups_flags

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
                'scopes': SERVICE_ACCOUNT_SCOPES,
            }],
            'metadata': {
                'items': [{
                    'key': 'startup-script',
                    'value': """#!/bin/bash
sudo apt-get install -y unzip
sudo apt-get install -y libmysqlclient-dev
sudo apt-get install -y python-pip python-dev

USER_HOME=/home/ubuntu
FORSETI_PROTOC_URL=https://raw.githubusercontent.com/GoogleCloudPlatform/forseti-security/master/data/protoc_url.txt

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
        PROTOC_DOWNLOAD_URL=$(curl -s $FORSETI_PROTOC_URL)

        if [ -z "$PROTOC_DOWNLOAD_URL" ]; then
            echo "No PROTOC_DOWNLOAD_URL set: $PROTOC_DOWNLOAD_URL"
            exit 1
        else
            wget $PROTOC_DOWNLOAD_URL
            unzip -o $(basename $PROTOC_DOWNLOAD_URL)
            sudo cp bin/protoc /usr/local/bin
        fi
fi

# Install Forseti Security
cd $USER_HOME
rm -rf forseti-*
pip install --upgrade pip
pip install --upgrade setuptools

cd $USER_HOME
wget -qO- {} | tar xvz
cd forseti-security-{}
python setup.py install

# Create the startup run script
read -d '' RUN_FORSETI << EOF
#!/bin/bash
# inventory command
{}
# scanner command
{}

EOF
echo "$RUN_FORSETI" > $USER_HOME/run_forseti.sh
chmod +x $USER_HOME/run_forseti.sh

(echo "0 * * * * $USER_HOME/run_forseti.sh") | crontab -
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
           RELEASE_VERSION,

           # run_forseti.sh
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
