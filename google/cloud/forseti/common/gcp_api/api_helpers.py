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

"""Helper functions for API clients."""

import google.auth
from google.auth import iam
from google.auth.credentials import with_scopes_if_required
from google.auth.transport import requests
from google.oauth2 import service_account

from google.cloud.forseti.common.gcp_api._base_repository import CLOUD_SCOPES


_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'


def get_delegated_credential(delegated_account, scopes):
    """Build delegated credentials required for accessing the gsuite APIs.

    Args:
        delegated_account (str): The account to delegate the service account to
            use.
        scopes (list): The list of required scopes for the service account.

    Returns:
        service_account.Credentials: Credentials as built by
        google.oauth2.service_account.
    """
    request = requests.Request()

    # Get the "bootstrap" credentials that will be used to talk to the IAM
    # API to sign blobs.
    bootstrap_credentials, _ = google.auth.default()

    bootstrap_credentials = with_scopes_if_required(
        bootstrap_credentials,
        list(CLOUD_SCOPES))

    # Refresh the boostrap credentials. This ensures that the information about
    # this account, notably the email, is populated.
    bootstrap_credentials.refresh(request)

    # Create an IAM signer using the bootstrap credentials.
    signer = iam.Signer(request,
                        bootstrap_credentials,
                        bootstrap_credentials.service_account_email)

    # Create OAuth 2.0 Service Account credentials using the IAM-based signer
    # and the bootstrap_credential's service account email.
    delegated_credentials = service_account.Credentials(
        signer, bootstrap_credentials.service_account_email, _TOKEN_URI,
        scopes=scopes, subject=delegated_account)

    return delegated_credentials


def flatten_list_results(paged_results, item_key):
    """Flatten a split-up list as returned by list_next() API.

    GCE 'list' APIs return results in the form:
      {item_key: [...]}
    with one dictionary for each "page" of results. This method flattens
    that to a simple list of items.

    Args:
        paged_results (list): A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key (str): The name of the key within the inner "items" lists
            containing the objects of interest.

    Returns:
        list: A list of items.
    """
    results = []
    for page in paged_results:
        results.extend(page.get(item_key, []))
    return results


def flatten_aggregated_list_results(paged_results, item_key):
    """Flatten a split-up list as returned by GCE "aggregatedList" API.

    The compute API's aggregatedList methods return a structure in
    the form:
      {
        items: {
          $group_value_1: {
            $item_key: [$items]
          },
          $group_value_2: {
            $item_key: [$items]
          },
          $group_value_3: {
            "warning": {
              message: "There are no results for ..."
            }
          },
          ...,
          $group_value_n, {
            $item_key: [$items]
          },
        }
      }
    where each "$group_value_n" is a particular element in the
    aggregation, e.g. a particular zone or group or whatever, and
    "$item_key" is some type-specific resource name, e.g.
    "backendServices" for an aggregated list of backend services.

    This method takes such a structure and yields a simple list of
    all $items across all of the groups.

    Args:
        paged_results (list): A list of paged API response objects.
            [{page 1 results}, {page 2 results}, {page 3 results}, ...]
        item_key (str): The name of the key within the inner "items" lists
            containing the objects of interest.

    Returns:
        list: A list of items.
    """
    items = []
    for page in paged_results:
        aggregated_items = page.get('items', {})
        for items_for_grouping in aggregated_items.values():
            for item in items_for_grouping.get(item_key, []):
                items.append(item)
    return items


def get_ratelimiter_config(global_configs, api_name):
    """Get rate limiter configuration.

    Args:
        global_configs (dict): Global configurations.
        api_name (String): The name of the api.

    Returns:
        float: Max calls
        float: quota period)
    """

    max_calls = global_configs.get(api_name, {}).get('max_calls')
    quota_period = global_configs.get(api_name, {}).get('period')
    return max_calls, quota_period
