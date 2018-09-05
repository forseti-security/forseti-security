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
"""GCP IAM Policy.

See: https://cloud.google.com/iam/reference/rest/v1/Policy
"""

import re

from google.cloud.forseti.common.gcp_type import errors
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.regular_exp import escape_and_globify


LOGGER = logger.get_logger(__name__)


def _get_iam_members(members):
    """Get a list of this binding's members as IamPolicyMembers.

    Args:
        members (list): A list of members (strings).

    Returns:
        list: A list of IamPolicyMembers.
    """
    return [IamPolicyMember.create_from(m) for m in members]


class IamPolicy(object):
    """GCP IAM Policy."""

    def __init__(self):
        """Initialize."""
        self.audit_configs = None
        self.bindings = []

    @classmethod
    def create_from(cls, policy_json):
        """Create an IamPolicy object from json representation.

        Args:
            policy_json (dict): The json representing the IAM policy.

        Returns:
            IamPolicy: An IamPolicy.
        """
        policy = cls()

        if not policy_json:
            raise errors.InvalidIamPolicyError(
                'Invalid policy {}'.format(policy_json))

        policy.bindings = [IamPolicyBinding.create_from(b)
                           for b in policy_json.get('bindings', [])]
        if 'auditConfigs' in policy_json:
            policy.audit_configs = IamAuditConfig.create_from(
                policy_json.get('auditConfigs'))

        return policy

    def __eq__(self, other):
        """Tests equality of IamPolicy.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True if equals, False otherwise.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.bindings == other.bindings and
                self.audit_configs == other.audit_configs)

    def __ne__(self, other):
        """Tests inequality of IamPolicy.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True if not equals, False otherwise.
        """
        return not self == other

    def __repr__(self):
        """String representation of IamPolicy.

        Returns:
            str: Representation of IamPolicy
        """
        if self.audit_configs:
            return 'IamPolicy: <bindings={}, audit_configs={}>'.format(
                self.bindings, self.audit_configs)
        return 'IamPolicy: <bindings={}>'.format(self.bindings)

    def is_empty(self):
        """Tests whether this policy's bindings are empty.

        Returns:
            bool: True if bindings are empty; False otherwise.
        """
        return not bool(self.bindings)


class IamPolicyBinding(object):
    """IAM Policy Binding."""

    def __init__(self, role_name, members=None):
        """Initialize.

        Args:
            role_name (str): The string name of the role.
            members (list): The role members of the policy binding.
        """
        if not role_name or not members:
            raise errors.InvalidIamPolicyBindingError(
                ('Invalid IAM policy binding: '
                 'role_name={}, members={}'.format(role_name, members)))
        self.role_name = role_name
        self.members = _get_iam_members(members)
        self.role_pattern = re.compile(escape_and_globify(role_name),
                                       flags=re.IGNORECASE)

    def __eq__(self, other):
        """Tests equality of IamPolicyBinding.

        Args:
            other (object): Object to compare.

        Returns:
            bool: Whether objects are equal.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.role_name == other.role_name and
                self.members == other.members)

    def __ne__(self, other):
        """Tests inequality of IamPolicyBinding.

        Args:
            other (object): Object to compare.

        Returns:
            bool: Whether objects are not equal.
        """
        return not self == other

    def __repr__(self):
        """String representation of IamPolicyBinding.

        Returns:
            str: The representation of IamPolicyBinding.
        """
        return 'IamBinding: <role_name={}, members={}>'.format(
            self.role_name, self.members)

    @classmethod
    def create_from(cls, binding):
        """Create an IamPolicyBinding from a binding dict.

        Args:
            binding (dict): The binding (role mapped to members).

        Returns:
            IamPolicyBinding: A new IamPolicyBinding created with the
                role and members.
        """
        if isinstance(binding, type(cls)):
            return binding
        try:
            return cls(binding.get('role'), binding.get('members'))
        except errors.InvalidIamPolicyMemberError:
            LOGGER.debug(
                'Invalid IAM policy member: %s.', binding.get('members'))
            return None

    def merge_members(self, other):
        """Add `other` members to mine if the role names are the same.

        Use case: merging members from ancestor bindings with the same role
        name.

        Args:
            other (IamPolicyBinding): the other IAM policy binding
        """
        if not isinstance(other, type(self)):
            raise errors.InvalidIamPolicyBindingError(
                'Cannot merge, other is not of type \'IamPolicyBinding\'')
        if other.role_name != self.role_name:
            return
        for member in other.members:
            if member not in self.members:
                self.members.append(member)


class IamPolicyMember(object):
    """IAM Policy Member.

    See https://cloud.google.com/iam/reference/rest/v1/Policy#Binding.

    Parse an identity from a policy binding.
    """

    ALL_USERS = 'allUsers'
    ALL_AUTH_USERS = 'allAuthenticatedUsers'
    member_types = {ALL_USERS, ALL_AUTH_USERS, 'user', 'group',
                    'serviceAccount', 'domain'}

    def __init__(self, member_type, member_name=None):
        """Initialize.

        Args:
            member_type (str): The string member type (see `member_types`).
            member_name (str): The string member name.
        """
        if not member_type or not self._member_type_exists(member_type):
            raise errors.InvalidIamPolicyMemberError(
                'Invalid policy member: {}'.format(member_type))
        self.type = member_type
        self.name = member_name
        self.name_pattern = None
        if member_name:
            self.name_pattern = re.compile(escape_and_globify(self.name),
                                           flags=re.IGNORECASE)

    def __eq__(self, other):
        """Tests equality of IamPolicyMember.

        Args:
            other (object): The object to compare.

        Returns:
            bool: Whether the objects are equal.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.type == other.type and
                self.name == other.name)

    def __ne__(self, other):
        """Tests inequality of IamPolicyMember.

        Args:
            other (object): The object to compare.

        Returns:
            bool: Whether the objects are not equal.
        """
        return not self == other

    def __hash__(self):
        """Hash function for IamPolicyMember.

        Returns:
            hash: The hashed object.
        """
        return hash((self.type, self.name))

    def __repr__(self):
        """String representation of IamPolicyMember.

        Returns:
            str: The representation of IamPolicyMember.
        """
        return '%s:%s' % (self.type, self.name)

    def _member_type_exists(self, member_type):
        """Determine if the member type exists in valid member types.

        Args:
            member_type (str): Member type.

        Returns:
            bool: If member type is valid.
        """
        return member_type in self.member_types

    @classmethod
    def create_from(cls, member):
        """Create an IamPolicyMember from the member identity string.

        Args:
            member (str): The IAM policy binding member.

        Returns:
            IamPolicyMember: Created from the member string.
        """
        identity_parts = member.split(':')
        member_name = None
        if len(identity_parts) > 1:
            member_name = identity_parts[1]
        return cls(identity_parts[0], member_name=member_name)

    def _is_matching_domain(self, other):
        """Determine whether IAM policy member belongs to domain.

        This applies to a situation where a rule has a `domain` style `members`
        specification and the policy to check specifies users.

        Args:
            other (IamPolicyMember): The policy binding member to check.

        Returns:
            bool: True if `other` is a member of the domain, False otherwise.
        """
        if self.type != 'domain' or other.type != 'user':
            return False

        try:
            _, domain = other.name.rsplit('@', 1)
        except ValueError:
            return False

        return self.name == domain

    def matches(self, other):
        """Determine if another member matches.

        Args:
            other (str): The policy binding member name.

        Returns:
            bool: True if the member matches this member, otherwise False.
        """
        other_member = None
        if isinstance(other, type(self)):
            other_member = other
        else:
            other_member = IamPolicyMember.create_from(other)

        # Bucket IAM supports a special "allUsers" and "allAuthenticatedUsers"
        # members, whose value is simply "allUsers" and "allAuthenticatedUsers",
        # without a colon separator and a second fragment.
        if (self.type == self.ALL_USERS and
                other_member.type == self.ALL_USERS):
            return True

        if (self.type == self.ALL_AUTH_USERS and
                other_member.type == self.ALL_AUTH_USERS):
            return True

        # Match if:
        # {member_type}:{member_name} regex-matches self's
        # {member_type}:{member_name} .
        if (self.type == other_member.type and
                self.name_pattern.match(other_member.name)):
            return True

        if self._is_matching_domain(other_member):
            return True

        return False


class IamAuditConfig(object):
    """IAM Audit Config.

    Captures the mapping from service to log type to exempted members for a
    project, folder or organization.
    """

    ALL_SERVICES = 'allServices'
    VALID_LOG_TYPES = frozenset(['AUDIT_READ', 'DATA_READ', 'DATA_WRITE'])

    def __init__(self, service_configs):
        """Initialize.

        Args:
            service_configs (dict): A dictionary mapping service names to
                dictionaries mapping log types to sets of exempeted members.
        """
        self.service_configs = service_configs

    def __eq__(self, other):
        """Tests equality of IamAuditConfig.

        Args:
            other (object): Object to compare.

        Returns:
            bool: Whether objects are equal.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.service_configs == other.service_configs

    def __ne__(self, other):
        """Tests inequality of IamAuditConfig.

        Args:
            other (object): Object to compare.

        Returns:
            bool: Whether objects are not equal.
        """
        return not self == other

    def __repr__(self):
        """String representation of IamAuditConfig.

        Returns:
            str: The representation of IamAuditConfig.
        """
        return 'IamAuditConfig: <service_configs={}>'.format(
            self.service_configs)

    @classmethod
    def create_from(cls, audit_configs_list):
        """Creates an IamAuditConfig from a list of auditConfig dicts.

        Args:
            audit_configs_list (list): A list of auditConfigs for each service.

        Returns:
            IamAuditConfig: A new IamAuditConfig created with the service audit
                configs.
        """
        service_configs = {}
        for audit_config in audit_configs_list:
            service_name = audit_config.get('service')
            log_configs = {}
            for log_config in audit_config.get('auditLogConfigs'):
                log_configs[log_config.get('logType')] = set(
                    log_config.get('exemptedMembers', []))
            if not service_name or not log_configs or None in log_configs:
                raise errors.InvalidIamAuditConfigError(
                    'Invalid IAM audit config: {}'.format(audit_config))
            service_configs[service_name] = log_configs
        return cls(service_configs)

    def merge_configs(self, other):
        """Adds `other` audit configs to mine, combining exempted member.

        Use case: merging audit configs from ancestor IAM policies.

        Args:
            other (IamAuditConfig): the other IAM audit configs
        """
        if not isinstance(other, type(self)):
            raise errors.InvalidIamAuditConfigError(
                'Cannot merge, other is not of type \'IamAuditConfig\'')
        for service_name, log_configs in other.service_configs.iteritems():
            if service_name not in self.service_configs:
                self.service_configs[service_name] = {}
            service_config = self.service_configs[service_name]
            for log_type, exemptions in log_configs.iteritems():
                service_config[log_type] = exemptions.union(service_config.get(
                    log_type, set()))
