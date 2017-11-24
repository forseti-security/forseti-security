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

"""Set up the gcloud environment and Forseti prerequisites.

This has been tested with python 2.7.
"""

import argparse

from environment import gcloud_env


def run():
    """Run the steps for the gcloud setup."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-cloudshell',
                        action='store_true',
                        help='Bypass Cloud Shell requirement')
    parser.add_argument('--no-iam-check',
                        action='store_true',
                        help='Bypass IAM check for user running script')
    parser.add_argument('--branch',
                        help='Which Forseti branch to deploy')

    group = parser.add_argument_group(title='regions')
    group.add_argument('--gcs-location',
                       help='The GCS bucket location')
    group.add_argument('--cloudsql-region',
                       help='The Cloud SQL region')

    network = parser.add_argument_group(title='network')
    network.add_argument('--host-project',
                         help='The host project id')
    network.add_argument('--vpc',
                         help='The VPC name where Forseti VM will run')
    network.add_argument('--subnet',
                         help='The subnetwork name where Forseti VM will run')

    email_params = parser.add_argument_group(title='email')
    email_params.add_argument('--sendgrid-api-key',
                              help='Sendgrid API key')
    email_params.add_argument('--notification-recipient-email',
                              help='Notification recipient email')
    email_params.add_argument('--gsuite-superadmin-email',
                              help='G Suite super admin email')

    args = vars(parser.parse_args())
    forseti_setup = gcloud_env.ForsetiGcpSetup(**args)
    forseti_setup.run_setup()


if __name__ == '__main__':
    run()
