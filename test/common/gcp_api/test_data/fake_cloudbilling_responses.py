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

"""Test data for Compute GCP api responses."""

FAKE_PROJECT_ID = "project1"

GET_PROJECTS_BILLING_INFO = """
{
 "name": "projects/projects/billingInfo",
 "projectId": "project1",
 "billingAccountName": "billingAccounts/000000-111111-222222",
 "billingEnabled": true
}
"""

GET_PROJECTS_BILLING_INFO_NOT_ENABLED = """
{
 "name": "projects/projects/billingInfo",
 "projectId": "project1"
}
"""

GET_BILLING_ACCOUNTS = """
{
 "billingAccounts": [
  {
   "name": "billingAccounts/000000-111111-222222",
   "open": true,
   "displayName": "My Billing Account",
   "masterBillingAccount": "billingAccounts/001122-AABBCC-DDEEFF"
  },
  {
   "name": "billingAccounts/001122-AABBCC-DDEEFF",
   "open": true,
   "displayName": "My Master Billing Account"
  }
 ]
}
"""

GET_BILLING_SUBACCOUNTS = """
{
 "billingAccounts": [
  {
   "name": "billingAccounts/000000-111111-222222",
   "open": true,
   "displayName": "My Billing Account",
   "masterBillingAccount": "billingAccounts/001122-AABBCC-DDEEFF"
  }
 ]
}
"""

GET_BILLING_IAM = """
{
 "etag": "BcDe123456z=",
 "bindings": [
  {
   "role": "roles/billing.admin",
   "members": [
    "user:foo@example.com"
   ]
  },
  {
   "role": "roles/logging.viewer",
   "members": [
    "group:auditors@example.com"
   ]
  }
 ]
}
"""

# Errors

PROJECT_NOT_FOUND = """
{
 "error": {
  "code": 404,
  "message": "Requested entity was not found.",
  "status": "NOT_FOUND"
 }
}
"""

PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "The caller does not have permission",
  "status": "PERMISSION_DENIED"
 }
}
"""
