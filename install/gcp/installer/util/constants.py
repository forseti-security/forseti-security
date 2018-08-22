# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Constants used for the setup of Forseti."""

import os
from enum import Enum


class FirewallRuleAction(Enum):
    """Firewall rule action object."""
    ALLOW = 'ALLOW'
    DENY = 'DENY'


class FirewallRuleDirection(Enum):
    """Firewall rule direction object."""
    INGRESS = 'INGRESS'
    EGRESS = 'EGRESS'


class DeploymentStatus(Enum):
    """Deployment status."""
    RUNNING = 'RUNNING'
    DONE = 'DONE'


MAXIMUM_LOADING_TIME_IN_SECONDS = 600

DEFAULT_BUCKET_FMT_V1 = 'gs://{}-data-{}'
DEFAULT_BUCKET_FMT_V2 = 'gs://forseti-{}-{}'

REGEX_MATCH_FORSETI_V1_INSTANCE_NAME = r'^forseti-security-\d+-vm$'

FORSETI_V1_RULE_FILES = [
    'bigquery_rules.yaml',
    'blacklist_rules.yaml',
    'bucket_rules.yaml',
    'cloudsql_rules.yaml',
    'firewall_rules.yaml',
    'forwarding_rules.yaml',
    'group_rules.yaml',
    'iam_rules.yaml',
    'iap_rules.yaml',
    'instance_network_interface_rules.yaml',
    'ke_rules.yaml',
    'gke_rules.yaml']

GCLOUD_MIN_VERSION = (180, 0, 0)
GCLOUD_VERSION_REGEX = r'Google Cloud SDK (.*)'
GCLOUD_ALPHA_REGEX = r'alpha.*'

SERVICE_ACCT_NAME_FMT = 'forseti-{}-{}-{}'
SERVICE_ACCT_EMAIL_FMT = '{}@{}.iam.gserviceaccount.com'

INPUT_DEPLOYMENT_TEMPLATE_FILENAME = {
    'server': 'deploy-forseti-server.yaml.in',
    'client': 'deploy-forseti-client.yaml.in'
}

INPUT_CONFIGURATION_TEMPLATE_FILENAME = {
    'server': 'forseti_conf_server.yaml.in',
    'client': 'forseti_conf_client.yaml.in'
}

NOTIFICATION_SENDER_EMAIL = 'forseti-notify@localhost.domain'

RESOURCE_TYPE_ARGS_MAP = {
    'organizations': ['organizations'],
    'folders': ['alpha', 'resource-manager', 'folders'],
    'projects': ['projects'],
    'forseti_project': ['projects'],
    'service_accounts': ['iam', 'service-accounts']
}

# Roles
GCP_READ_IAM_ROLES = [
    'roles/browser',
    'roles/compute.networkViewer',
    'roles/iam.securityReviewer',
    'roles/appengine.appViewer',
    'roles/bigquery.dataViewer',
    'roles/servicemanagement.quotaViewer',
    'roles/serviceusage.serviceUsageConsumer',
    'roles/cloudsql.viewer'
]

GCP_WRITE_IAM_ROLES = [
    'roles/compute.securityAdmin'
]

PROJECT_IAM_ROLES_SERVER = [
    'roles/storage.objectViewer',
    'roles/storage.objectCreator',
    'roles/cloudsql.client',
    'roles/logging.logWriter'
]

PROJECT_IAM_ROLES_CLIENT = [
    'roles/storage.objectViewer',
    'roles/logging.logWriter'
]

SVC_ACCT_ROLES = [
    'roles/iam.serviceAccountTokenCreator'
]

# Required APIs
REQUIRED_APIS = [
    {'name': 'Admin SDK',
     'service': 'admin.googleapis.com'},
    {'name': 'AppEngine Admin',
     'service': 'appengine.googleapis.com'},
    {'name': 'BigQuery',
     'service': 'bigquery-json.googleapis.com'},
    {'name': 'Cloud Billing',
     'service': 'cloudbilling.googleapis.com'},
    {'name': 'Cloud Resource Manager',
     'service': 'cloudresourcemanager.googleapis.com'},
    {'name': 'Cloud SQL',
     'service': 'sql-component.googleapis.com'},
    {'name': 'Cloud SQL Admin',
     'service': 'sqladmin.googleapis.com'},
    {'name': 'Compute Engine',
     'service': 'compute.googleapis.com'},
    {'name': 'Deployment Manager',
     'service': 'deploymentmanager.googleapis.com'},
    {'name': 'IAM',
     'service': 'iam.googleapis.com'}
]

# Org Resource Types
RESOURCE_TYPES = ['organization', 'folder', 'project']

# Paths
ROOT_DIR_PATH = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(__file__)))))

RULES_DIR_PATH = os.path.abspath(
    os.path.join(
        ROOT_DIR_PATH, 'rules'))

FORSETI_SRC_PATH = os.path.join(
    ROOT_DIR_PATH, 'google', 'cloud', 'forseti')

FORSETI_CONF_PATH = ('{bucket_name}/configs/'
                     'forseti_conf_{installation_type}.yaml')

DEPLOYMENT_TEMPLATE_OUTPUT_PATH = '{}/deployment_templates/'

VERSIONFILE_REGEX = r'__version__ = \'(.*)\''

# Message templates
MESSAGE_GSUITE_DATA_COLLECTION = (
    'To complete setup for G Suite Groups data collection, '
    'follow the steps here:\n\n    '
    'https://forsetisecurity.org/docs/latest/configure/'
    'inventory/gsuite.html\n')

MESSAGE_SKIP_EMAIL = (
    'If you would like to enable email notifications via '
    'SendGrid, please refer to:\n\n'
    '    '
    'http://forsetisecurity.org/docs/latest/configure/notifier/'
    'index.html#email-notifications-with-sendgrid\n\n')

MESSAGE_HAS_ROLE_SCRIPT = (
    'Some roles could not be assigned during the installation. '
    'A script `grant_forseti_roles.sh` has been generated in '
    'your cloud shell directory located at ~/forseti-security with '
    'the necessary commands to assign those roles. Please run this '
    'script to assign the roles so that Forseti will work properly.\n\n')

MESSAGE_ENABLE_GSUITE_GROUP_INSTRUCTIONS = (
    'IMPORTANT NOTE\n'
    'Your Forseti Security Installation will not work until '
    'you enable GSuite data collection:\n'
    'https://forsetisecurity.org/docs/latest/configure/'
    'inventory/gsuite.html\n')

MESSAGE_FORSETI_CONFIGURATION_INSTRUCTIONS = (
    'For instructions on how to change your roles or configuration files:\n'
    'http://forsetisecurity.org/docs/latest/configure/')

MESSAGE_FORSETI_SENDGRID_INSTRUCTIONS = (
    'If you would like to enable email notifications via SendGrid,'
    ' please refer to:\n'
    'http://forsetisecurity.org/docs/latest/configure/notifier/'
    'index.html#email-notifications-with-sendgrid\n'
)

MESSAGE_ASK_GSUITE_SUPERADMIN_EMAIL = (
    'To read G Suite Groups and Users data, '
    'please provide a G Suite super admin email address. '
    'This step is optional. \n'
    'See https://forsetisecurity.org/docs/latest/setup/install.html'
    'to know what will not work without G Suite integration.\n'
)

MESSAGE_ASK_SENDGRID_API_KEY = (
    'Forseti can send email notifications through SendGrid '
    'API Key')

MESSAGE_SKIP_SENDGRID_API_KEY = (
    'Skipping SendGrid configuration.\n')

MESSAGE_FORSETI_CONFIGURATION_ACCESS_LEVEL = (
    'Forseti can be configured to access an '
    'organization, folder, or project.')

MESSAGE_NO_CLOUD_SHELL = (
    'Forseti highly recommends running this setup within '
    'Cloud Shell. If you would like to run the setup '
    'outside Cloud Shell, please be sure to do the '
    'following:\n\n'
    '1) Create a project.\n'
    '2) Enable billing for the project.\n'
    '3) Install gcloud and authenticate your account using '
    '"gcloud auth login".\n'
    '4) Set your project using '
    '"gcloud config project set <PROJECT_ID>".\n'
    '5) Run this setup again, with the --no-cloudshell flag, '
    'i.e.\n\n\tpython install/gcp_installer.py --no-cloudshell\n')

MESSAGE_FORSETI_CONFIGURATION_GENERATED = (
    'Forseti configuration file(s) has been generated.\n\n'
    '{forseti_config_file_paths}\n\n')

MESSAGE_FORSETI_CONFIGURATION_GENERATED_DRY_RUN = (
    'A Forseti configuration file has been generated. '
    'After you create your deployment, copy this file to '
    'the bucket created in the deployment:\n\n'
    '    gsutil cp {} {}/configs/forseti_conf_server.yaml\n\n')

MESSAGE_DEPLOYMENT_HAD_ISSUES = (
    'Your deployment had some issues. Please review the error '
    'messages. If you need help, please either file an issue '
    'on our Github Issues or email '
    'discuss@forsetisecurity.org.\n')

MESSAGE_FORSETI_BRANCH_DEPLOYED = (
    'Forseti (branch/version: {}) has been deployed to GCP.\n\n')

MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION = (
    'Your generated Deployment Manager template(s) can be '
    'found here:\n\n{deployment_template_gcs_paths}\n\n')

MESSAGE_VIEW_DEPLOYMENT_DETAILS = (
    'You can view the details of your deployment in the '
    'Cloud Console:\n\n    '
    'https://console.cloud.google.com/deployments/details/'
    '{}?project={}&organizationId={}\n\n')

MESSAGE_GCLOUD_VERSION_MISMATCH = (
    'You need the following gcloud setup:\n\n'
    'gcloud version >= {}\n'
    'gcloud alpha components\n\n'
    'To install gcloud alpha components: '
    'gcloud components install alpha\n\n'
    'To update gcloud: gcloud components update\n')

MESSAGE_CREATE_ROLE_SCRIPT = (
    'One or more roles could not be assigned. Writing a '
    'script with the commands to assign those roles. Please '
    'give this script to someone (like an admin) who can '
    'assign these roles for you. If you do not assign these '
    'roles, Forseti may not work properly!')

MESSAGE_BILLING_NOT_ENABLED = (
    '\nIt seems that billing is not enabled for your project. '
    'You can check whether billing has been enabled in the '
    'Cloud Platform Console:\n\n'
    '    https://console.cloud.google.com/billing/linkedaccount?'
    'project={}&organizationId={}\n\n'
    'Once you have enabled billing, re-run this setup.\n')

MESSAGE_NO_ORGANIZATION = (
    'You need to have an organization set up to use Forseti. '
    'Refer to the following documentation for more information.\n\n'
    'https://cloud.google.com/resource-manager/docs/'
    'creating-managing-organization')

MESSAGE_RUN_FREQUENCY = (
    'Forseti will run once every 2 hours, a new run will not start until '
    'the previous run is completed. You can configure the run '
    'frequency in the server deployment template field "run-frequency" '
    'and update the deployment using the deployment manager.')

MESSAGE_DEPLOYMENT_ERROR = (
    'Error occurred during the deployment, please check the Forseti '
    'FAQ for more information ('
    'https://forsetisecurity.org/docs/latest/faq/#installation-and-deployment'
    '), exiting...'
)

# Questions templates
QUESTION_ENABLE_WRITE_ACCESS = (
    'Enable write access for Forseti? '
    'This allows Forseti to make changes to policies '
    '(e.g. for Enforcer) (y/n): ')

QUESTION_GSUITE_SUPERADMIN_EMAIL = (
    'Email: ')

QUESTION_SENDGRID_API_KEY = (
    'What is your SendGrid API key? '
    '(press [enter] to skip): ')

QUESTION_NOTIFICATION_RECIPIENT_EMAIL = (
    'At what email address do you want to receive '
    'notifications? (press [enter] to skip): ')

QUESTION_FORSETI_CONFIGURATION_ACCESS_LEVEL = (
    'At what level do you want to enable Forseti '
    'read (and optionally write) access?: ')

QUESTION_ACCESS_TO_GRANT_ROLES = (
    'Do you have access to grant Forseti IAM '
    'roles on the target {}? (y/n): ')

QUESTION_CHOOSE_FOLDER = (
    'To find the folder, go to Cloud Console:\n\n'
    '\thttps://console.cloud.google.com/'
    'cloud-resource-manager?organizationId={}\n\n'
    'Enter the folder id where you want '
    'Forseti to crawl for data: ')

QUESTION_SHOULD_MIGRATE_FROM_V1 = (
    'Forseti v1 detected, would you like to migrate the '
    'existing configurations to v2? (y/n): '
)

QUESTION_CONTINUE_IF_AUTHED_USER_IS_NOT_IN_DOMAIN = (
    '\n'
    'The currently authenticated user running the installer '
    'is not in the domain that Forseti is being installed to.\n'
    'If you wish to continue, you need to grant the '
    'compute.osLoginExternalUser role to your user on the org level, '
    'in order to have ssh access to the Forseti client VM.\n'
    'Would you like to continue? (y/n): '
)
