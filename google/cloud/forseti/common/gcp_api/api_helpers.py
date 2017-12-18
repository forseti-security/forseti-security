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
from oauth2client import service_account

from google.cloud.forseti.common.gcp_api import errors as api_errors


def credential_from_keyfile(keyfile_name, scopes, delegated_account):
    """Build delegated credentials required for accessing the gsuite APIs.

    Args:
        keyfile_name (str): The filename to load the json service account key
            from.
        scopes (list): The list of required scopes for the service account.
        delegated_account (str): The account to delegate the service account to
            use.

    Returns:
        OAuth2Credentials: Credentials as built by oauth2client.

    Raises:
        api_errors.ApiExecutionError: If fails to build credentials.
    """
    try:
        credentials = (
            service_account.ServiceAccountCredentials.from_json_keyfile_name(
                keyfile_name, scopes=scopes))
    except (ValueError, KeyError, TypeError, IOError) as e:
        raise api_errors.ApiInitializationError(
            'Error building admin api credential: %s' % e)
    return credentials.create_delegated(delegated_account)


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
