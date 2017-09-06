#
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

"""Utils for IAM Explain testing."""

import os


class GcpEnvironment(object):
    def __init__(self):
        self.organization_id = os.environ.get('EXPLAIN_GCP_ORG_ID')
        self.gsuite_sa = os.environ.get('EXPLAIN_GCP_GROUPS_SA')
        self.crawling_sa = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        self.gsuite_admin_email = os.environ.get('EXPLAIN_GCP_CRAWLING_SA')
        self.passphrase = os.environ.get('EXPLAIN_GCP_PASSPHRASE')
        if not all([self.organization_id,
                    self.gsuite_sa,
                    self.crawling_sa,
                    self.gsuite_admin_email,
                    self.passphrase]):
            raise Exception('Missing configuration items')


def gcp_env():
    return GcpEnvironment()


def gcp_configured():
    try:
        GcpEnvironment()
        return True
    except Exception:
        return False
