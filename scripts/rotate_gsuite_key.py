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

"""Rotate G Suite key.

This has been tested with python 2.7.
"""

from __future__ import print_function

import argparse
import json
import os
import sys

from gcp_setup.environment import gcloud_env

def run(argv):
    """Rotate G Suite key."""
    if len(argv) < 2:
        print('%s: Missing path to key. Exiting.' % argv[0])
        sys.exit(1)
    key_path = argv[1]
    curr_private_key_id = None
    service_account = None
    if os.path.exists(key_path):
        try:
            with open(key_path) as json_data:
                key_contents = json.load(json_data)
                service_account = key_contents.get('client_email')
                curr_private_key_id = key_contents.get('private_key_id')
        except ValueError as verr:
            print(verr)
            sys.exit(1)

    # delete current key
    if curr_private_key_id and service_account:
        print('Delete key id=%s' % curr_private_key_id)
        return_code, out, err = gcloud_env.run_command([
            'gcloud', 'iam', 'service-accounts', 'keys',
            'delete', curr_private_key_id, '--quiet',
            '--iam-account=%s' % service_account])
        if return_code:
            print(err)
        else:
            print(out)

    # create new key
    if service_account:
        print('Create new key for %s' % service_account)
        return_code, out, err = gcloud_env.run_command([
            'gcloud', 'iam', 'service-accounts', 'keys',
            'create', key_path,
            '--iam-account=%s' % service_account])
        if return_code:
            print(err)
        else:
            print(out)


if __name__ == '__main__':
    run(sys.argv)
