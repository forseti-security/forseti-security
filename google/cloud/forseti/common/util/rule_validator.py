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
"""Validation routines for GCE firewall rules."""
from __future__ import unicode_literals

import re

# Allowed items in a firewall rule.
ALLOWED_RULE_ITEMS = frozenset(('allowed', 'denied', 'description', 'direction',
                                'disabled', 'name', 'network', 'priority',
                                'sourceRanges', 'destinationRanges',
                                'sourceTags', 'targetTags', 'logConfig'))

# Top level required items for a valid rule.
REQUIRED_RULE_ITEMS = frozenset(('name', 'network'))

# Keys that allow a list but only up to 256 entries.
MAX_256_VALUE_KEYS = frozenset(
    ['sourceRanges', 'sourceTags', 'targetTags', 'destinationRanges'])

# Name restrictions described at
# https://cloud.google.com/compute/docs/reference/rest/v1/firewalls
VALID_RESOURCE_NAME_RE = re.compile('(?:^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$)')


def validate_gcp_rule(rule):
    """Validates that a rule is sound and meets the requirements of GCP.

    Validation is based on reference:
    https://cloud.google.com/compute/docs/reference/beta/firewalls and
    https://cloud.google.com/compute/docs/vpc/firewalls#gcp_firewall_rule_summary_table


    Args:
      rule: A dict representation of the rule to be validated.

    Returns:
      err_str: A string describing the reason the rule is invalid. None if
          rule passes validation.
    """
    # Keys must be from the set of allowed items.
    key_set = set(rule)
    unknown_keys = key_set - ALLOWED_RULE_ITEMS
    if unknown_keys:
        # This is probably the result of a API version upgrade that didn't
        # properly update this function (or a broken binary).
        return ('An unexpected entry exists in a firewall rule dict:'
                ' "%s".' % ','.join(list(unknown_keys)))

    # Check for the presense of all items from REQUIRED_RULE_ITEMS.
    missing_keys = REQUIRED_RULE_ITEMS - key_set
    if missing_keys:
        return ('Rule missing required field(s):"%s".' %
                ','.join(list(missing_keys)))

    # Direction defaults to INGRESS
    direction = rule.get('direction', 'INGRESS')

    # Direction must be either INGRESS or EGRESS
    if direction not in ['INGRESS', 'EGRESS']:
        return ('Rule "direction" must be either "INGRESS" or "EGRESS":'
                ' "%s".' % rule)

    # Ingress rules cannot have destinationRanges.
    if direction == 'INGRESS' and 'destinationRanges' in rule:
        return ('Ingress rules cannot include "destinationRanges": '
                '"%s".' % rule)

    # Egress rules cannot have sourceRanges or sourceTags.
    if direction == 'EGRESS' and key_set.intersection(
            ['sourceRanges', 'sourceTags']):
        return ('Egress rules cannot include "sourceRanges", "sourceTags": '
                '"%s".' % rule)

    # Keys that allow repeated values have a maximum of 256 values.
    for key, values in ((key, rule.get(key, [])) for key in MAX_256_VALUE_KEYS):
        if len(values) > 256:
            return ('Rule entry "%s" must contain 256 or fewer values:'
                    ' "%s".' % (key, rule))

    # Network tags resemble valid domain names.
    for tag_type in ['sourceTags', 'targetTags']:
        for tag in rule.get(tag_type, []):
            if VALID_RESOURCE_NAME_RE.match(tag) is None:
                return ('Rule tag does not match valid GCP resource'
                        ' name regex "%s": "%s".' % (
                            VALID_RESOURCE_NAME_RE.pattern, rule['name']))

    # Rules must have either allowed or denied sections, but cannot have both.
    if not ('allowed' in rule) ^ ('denied' in rule):
        return ('Rule must contain one of "allowed" or "denied" entries:'
                ' "%s".' % rule)

    # IPProtocol must be specified in allowed rules.
    for allow in rule.get('allowed', []):
        if 'IPProtocol' not in allow:
            return (
                'Allow rule %s missing required field "IPProtocol": "%s".' % (
                    rule['name'], allow))

    # IPProtocol must be specified in denied rules.
    for deny in rule.get('denied', []):
        if 'IPProtocol' not in deny:
            return (
                'Deny rule %s missing required field "IPProtocol": "%s".' % (
                    rule['name'], deny))

    # Priority is optional but must be an integer between 0-65535 inclusive.
    if 'priority' in rule:
        try:
            priority = int(rule['priority'])
        except ValueError:
            return ('Rule "priority" could not be converted to an'
                    ' integer: "%s".' % rule)
        if priority < 0 or priority > 65535:
            return 'Rule "priority" out of range 0-65535: "%s".' % rule

    # Rule name must look like a domain.
    if VALID_RESOURCE_NAME_RE.match(rule['name']) is None:
        return ('Rule name does not match valid GCP resource name regex '
                '"%s": "%s".' % (VALID_RESOURCE_NAME_RE.pattern, rule['name']))
