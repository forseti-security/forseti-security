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

"""An AppEngine Application.

See: https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps
"""

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-param-doc

# pylint: disable=too-many-instance-attributes
class Application(object):
    """Represents Instance resource."""

    def __init__(self, **kwargs):
        """AppEngine Application resource."""
        self.project_id = kwargs.get('project_id')
        self.name = kwargs.get('name')
        self.app_id = kwargs.get('app_id')
        self.dispatch_rules = kwargs.get('dispatch_rules')
        self.auth_domain = kwargs.get('auth_domain')
        self.location_id = kwargs.get('location_id')
        self.code_bucket = kwargs.get('code_bucket')
        self.default_cookie_expiration = kwargs.get('default_cookie_expiration')
        self.serving_status = kwargs.get('serving_status')
        self.default_hostname = kwargs.get('default_hostname')
        self.default_bucket = kwargs.get('default_bucket')
        self.iap = kwargs.get('iap')
        self.gcr_domain = kwargs.get('gcr_domain')
        self.raw_application = kwargs.get('raw_application')
