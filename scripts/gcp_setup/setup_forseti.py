# Copyright 2017 Google Inc.
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
    parser.add_argument('--branch',
                        help='Which Forseti branch to deploy')
    group = parser.add_argument_group(title='regions')
    group.add_argument('--gcs-location',
                       help='The GCS bucket location')
    group.add_argument('--cloudsql-region',
                       help='The Cloud SQL region')

    args = vars(parser.parse_args())
    forseti_setup = gcloud_env.ForsetiGcpSetup(**args)
    forseti_setup.run_setup()


if __name__ == '__main__':
    run()
