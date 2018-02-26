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

from installer.forseti_server_installer import ForsetiServerInstaller
from installer.forseti_client_installer import ForsetiClientInstaller


def run():
    """Run the steps for the gcloud setup."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-cloudshell',
                        action='store_true',
                        help='Bypass Cloud Shell requirement')
    parser.add_argument('--no-iam-check',
                        action='store_true',
                        help='Bypass IAM check for user running script')
    parser.add_argument('--advanced',
                        action='store_true',
                        help='Advanced setup mode (more options)')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help=('Generate config files but do not modify '
                              'GCP infrastructure (i.e. do not actually '
                              'set up Forseti)'))
    parser.add_argument('--type',
                        choices=['client', 'server'],
                        help='Type of the installation, '
                             'either client or server')

    group = parser.add_argument_group(title='regions')
    group.add_argument('--gcs-location',
                       help='The GCS bucket location',
                       default='us-central1')
    group.add_argument('--cloudsql-region',
                       help='The Cloud SQL region',
                       default='us-central1')

    email_params = parser.add_argument_group(title='email')
    email_params.add_argument('--sendgrid-api-key',
                              help='Sendgrid API key')
    email_params.add_argument('--notification-recipient-email',
                              help='Notification recipient email')
    email_params.add_argument('--gsuite-superadmin-email',
                              help='G Suite super admin email')
    args = vars(parser.parse_args())

    # Set the current date time stamp
    args['datetimestamp'] = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    if not args.get('type'):
        # If the user didn't specify a type, install both server and client
        ForsetiServerInstaller(**args).run_setup()
        ForsetiClientInstaller(**args).run_setup()
        return

    if args.get('type') == 'server':
        forseti_setup = ForsetiServerInstaller(**args)
    else:
        forseti_setup = ForsetiClientInstaller(**args)

    forseti_setup.run_setup()


if __name__ == '__main__':
    run()
