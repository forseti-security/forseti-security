# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""A Billing Account Resource."""

import json

from google.cloud.forseti.common.gcp_type import resource


class BillingAccountLifecycleState(resource.LifecycleState):
    """Represents the Billing Account's LifecycleState."""
    pass


class BillingAccount(resource.Resource):
    """BillingAccount Resource."""

    RESOURCE_NAME_FMT = 'billingAccounts/%s'

    def __init__(
            self,
            billing_account_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            lifecycle_state=BillingAccountLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            billing_account_id (str): The billing account id.
            full_name (str): The full resource name and ancestory.
            data (str): Resource representation of the billing account.
            name (str): The billing account's unique GCP name, with the format
                "billingAccounts/{id}".
            display_name (str): The billing account's display name.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The billing accounts's lifecycle
                state.
        """
        super(BillingAccount, self).__init__(
            resource_id=billing_account_id,
            resource_type=resource.ResourceType.BILLING_ACCOUNT,
            name=name,
            display_name=display_name,
            parent=parent,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Creates a billing account from a JSON string.

        Args:
            parent (Resource): resource this billing account belongs to.
            json_string (str): JSON string of a billing account GCP resource.

        Returns:
            BillingAccount: billing account resource.
        """
        acct_dict = json.loads(json_string)
        name = acct_dict['name']
        acct_id = name.split('/')[-1]
        full_name = '{}billing_account/{}/'.format(parent.full_name, acct_id)
        return cls(
            billing_account_id=acct_id,
            full_name=full_name,
            data=json_string,
            name=name,
            display_name=acct_dict.get('displayName'),
            parent=parent)
