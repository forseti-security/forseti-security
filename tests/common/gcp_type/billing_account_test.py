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

"""Tests the Billing Account resource"""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import billing_account
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import resource_util


_BILLING_ACCT_JSON = """
{
  "name": "billingAccounts/000000-111111-222222",
  "open": true,
  "displayName": "My Billing Account",
  "masterBillingAccount": "billingAccounts/001122-AABBCC-DDEEFF"
}"""


class BillingAccountTest(ForsetiTestCase):
    """Test Billing Account resource."""

    def setUp(self):
        self.org_234 = organization.Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

    def test_getters_are_correct(self):
        """Tests whether the Billing Account methods return expected data."""
        billing_acct = billing_account.BillingAccount(
            '000000-111111-222222',
            display_name='My Billing Account',
            parent=self.org_234)

        self.assertEqual('000000-111111-222222', billing_acct.id)
        self.assertEqual('billing_account', billing_acct.type)
        self.assertEqual('billingAccounts/000000-111111-222222',
                         billing_acct.name)
        self.assertEqual('My Billing Account', billing_acct.display_name)
        self.assertEqual(self.org_234, billing_acct.parent)

    def test_create_from_resource_utils(self):
        """Tests creating a Billing Account using resource_util."""
        billing_acct = resource_util.create_resource(
            resource_id='000000-111111-222222',
            resource_type='billing_account',
            full_name='organization/234/billing_account/000000-111111-222222/',
            parent=self.org_234)

        self.assertEqual('000000-111111-222222', billing_acct.id)
        self.assertEqual('billing_account', billing_acct.type)
        self.assertEqual('billingAccounts/000000-111111-222222',
                         billing_acct.name)
        self.assertEqual(
            'organization/234/billing_account/000000-111111-222222/',
            billing_acct.full_name)

    def test_get_billing_account_ancestors(self):
        """Tests getting ancestors from a billing account full name."""
        ancestors = resource_util.get_ancestors_from_full_name(
            'organization/234/billing_account/000000-111111-222222/')

        self.assertEqual(2, len(ancestors))
        self.assertEqual('billingAccounts/000000-111111-222222',
                         ancestors[0].name)
        self.assertEqual('organizations/234', ancestors[1].name)

    def test_billing_account_from_json(self):
        """Tests creation of a billing account from a JSON string."""
        billing_acct = billing_account.BillingAccount.from_json(
            self.org_234, _BILLING_ACCT_JSON)
        self.assertEqual('000000-111111-222222', billing_acct.id)
        self.assertEqual('billing_account', billing_acct.type)
        self.assertEqual('billingAccounts/000000-111111-222222',
                         billing_acct.name)
        self.assertEqual(
            'organization/234/billing_account/000000-111111-222222/',
            billing_acct.full_name)


if __name__ == '__main__':
    unittest.main()
