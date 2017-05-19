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

"""Provides formatting functions for violations"""

def format_policy_violation(violation):
    """Format the policy violation data into a tuple.

    Also flattens the RuleViolation, since it consists of the resource,
    rule, and members that don't meet the rule criteria.

    Various properties of RuleViolation may also have values that exceed the
    declared column length, so truncate as necessary to prevent MySQL errors.

    Args:
        violation: The Policy RuleViolation.

    Yields:
        A tuple of the rule violation properties.
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

    role = violation.role
    if role:
        role = role[:255]

    iam_members = violation.members
    if iam_members:
        members = [str(iam_member)[:255] for iam_member in iam_members]
    else:
        members = []

    for member in members:
        yield (resource_type,
               resource_id,
               rule_name,
               violation.rule_index,
               violation.violation_type,
               role,
               member)

def format_buckets_acl_violation(violation):
    """Format the bucket acls violation data into a tuple.

    Also flattens the RuleViolation, since it consists of the resource,
    rule, and members that don't meet the rule criteria.

    Various properties of RuleViolation may also have values that exceed the
    declared column length, so truncate as necessary to prevent MySQL errors.

    Args:
        violation: The bucket acls RuleViolation.

    Yields:
        A tuple of the rule violation properties.
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

    role = violation.role
    if role:
        role = role[:255]

    entity = violation.entity
    if entity:
        entity = entity[:255]

    email = violation.email
    if email:
        email = email[:255]

    domain = violation.domain
    if domain:
        domain = domain[:255]

    bucket = violation.bucket
    if bucket:
        bucket = bucket[:255]

    yield (resource_type,
           resource_id,
           rule_name,
           violation.rule_index,
           violation.violation_type,
           role,
           entity,
           email,
           domain,
           bucket)

def format_cloudsql_acl_violation(violation):
    """Format the CloudSQL acls violation data into a tuple.

    Also flattens the RuleViolation, since it consists of the resource,
    rule, and members that don't meet the rule criteria.

    Various properties of RuleViolation may also have values that exceed the
    declared column length, so truncate as necessary to prevent MySQL errors.

    Args:
        violation: The cloudsql acls RuleViolation.

    Yields:
        A tuple of the rule violation properties.
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

    instance_name = violation.instance_name
    if instance_name:
        instance_name = instance_name[:255]

    authorized_networks = str(violation.authorized_networks)
    if authorized_networks:
        authorized_networks = authorized_networks[:255]

    ssl_enabled = str(violation.ssl_enabled)

    yield (resource_type,
           resource_id,
           rule_name,
           violation.rule_index,
           violation.violation_type,
           instance_name,
           authorized_networks,
           ssl_enabled)
