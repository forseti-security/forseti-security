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

"""Provides formatting functions for violations"""

import json


def format_violation(violation):
    """Format the policy violation data into a tuple.

    Also flattens the RuleViolation, since it consists of the resource,
    rule, and members that don't meet the rule criteria.

    Various properties of RuleViolation may also have values that exceed the
    declared column length, so truncate as necessary to prevent MySQL errors.

    Args:
        violation (namedtuple): The Policy RuleViolation. This is a named
            tuple.

    Yields:
        tuple: A tuple of the rule violation properties.
    """
    resource_type = violation.resource_type
    if resource_type:
        resource_type = resource_type[:255]

    resource_id = violation.resource_id
    if resource_id:
        resource_id = str(resource_id)[:255]

    rule_name = violation.rule_name
    if rule_name:
        rule_name = rule_name[:255]
    yield (resource_type,
           resource_id,
           rule_name,
           violation.rule_index,
           violation.violation_type,
           json.dumps(violation.violation_data, sort_keys=True))


# TODO: refactor groups scanner to use the generic violations format
def format_groups_violation(violation):
    """Format the groups violation data into a tuple.

    Args:
        violation (namedtuple): The groups violation. This is a named tuple
            (see rules.py in google.cloud.forseti.scanner.audit).

    Yields:
        tuple: A tuple of the violation properties.
    """
    member_email = violation.member_email
    if member_email:
        member_email = member_email[:255]

    group_email = violation.parent.member_email
    if group_email:
        group_email = group_email[:255]

    violated_rule_names = json.dumps(
        violation.violated_rule_names, sort_keys=True)

    yield (member_email,
           group_email,
           violated_rule_names)
