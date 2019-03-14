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

""" GCP Installer.
This has been tested with python 2.7.
"""

import argparse
import datetime
import site
import sys

from installer.util.utils import run_command

INSTALLER_REQUIRED_PACKAGES = [
    'ruamel.yaml'
]


def install(package_name):
    """Install package.
    Args:
        package_name (str): Name of the package to install.
    """
    # pip's python api is deprecated, we will run the pip command
    # through subprocess directly instead.
    return_code, _, err = run_command(
        ['pip', 'install', package_name, '--user'])

    if return_code:
        print 'Error installing package {}'.format(package_name)
        print err
        sys.exit(1)


def install_required_packages():
    """Install required packages."""
    for package in INSTALLER_REQUIRED_PACKAGES:
        install(package)


def run():
    """Run the steps for the gcloud setup."""

    # We need to install all the required packages before importing our modules
    # Installing required packages
    install_required_packages()
    site.main() # Load up the package

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--no-cloudshell',
                        action='store_true',
                        help='Bypass Cloud Shell requirement')
    parser.add_argument('--service-account-key-file',
                        help=('Absolute path and filename for service account '
                              'key file'))
    parser.add_argument('--type',
                        choices=['client', 'server'],
                        help='Type of the installation, '
                             'either client or server')
    parser.add_argument('--composite-root-resources',
                        help='The resource ids to be inventoried.\n'
                             'Without this flag, the entire org '
                             'will be attempted.\n'
                             'Resources must be comma-separated and '
                             'in the form type/id,\nwhere type is '
                        'one of organizations, folders, or projects.')
    parser.add_argument('--project-id',
                        help='The project id for the forseti installaltion.')

    group = parser.add_argument_group(title='regions')
    group.add_argument('--gcs-location',
                       help='The GCS bucket location',
                       default='us-central1')
    group.add_argument('--cloudsql-region',
                       help='The Cloud SQL region',
                       default='us-central1')

    network = parser.add_argument_group(title='network')
    network.add_argument('--vpc-host-project-id',
                         help='The project id that is hosting the network '
                         'resources.')
    network.add_argument('--vpc-host-network',
                         help='The VPC name where Forseti VM will run.')
    network.add_argument('--vpc-host-subnetwork',
                         help='The subnetwork name where Forseti VM will run.')

    email_params = parser.add_argument_group(title='email')
    email_params.add_argument('--sendgrid-api-key',
                              help='Sendgrid API key')
    email_params.add_argument('--notification-recipient-email',
                              help='Notification recipient email')
    email_params.add_argument('--skip-sendgrid-config',
                              action='store_true',
                              help='Skip Sendgrid cofiguration')
    email_params.add_argument('--gsuite-superadmin-email',
                              help='G Suite super admin email')

    args = vars(parser.parse_args())

    # Set the current date time stamp
    args['datetimestamp'] = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    # import installers and configs
    from installer.forseti_server_installer import ForsetiServerInstaller
    from installer.forseti_client_installer import ForsetiClientInstaller
    from installer.configs.client_config import ClientConfig
    from installer.configs.server_config import ServerConfig
    client_config = ClientConfig(**args)
    server_config = ServerConfig(**args)

    if not args.get('type'):
        # If the user didn't specify a type, install both server and client
        forseti_server = ForsetiServerInstaller(server_config)
        instructions = forseti_server.run_setup(final_setup=False)
        # Server and client will have the same identifier to keep them
        # consistent.
        client_config.identifier = server_config.identifier
        ForsetiClientInstaller(client_config, forseti_server).run_setup(
            setup_continuation=True,
            previous_instructions=instructions)
        return

    if args.get('type') == 'server':
        forseti_setup = ForsetiServerInstaller(server_config)
    else:
        forseti_setup = ForsetiClientInstaller(client_config)

    forseti_setup.run_setup()


if __name__ == '__main__':
    run()
