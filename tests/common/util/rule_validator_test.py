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
"""Testing GCP firewall rule validation library."""
from __future__ import unicode_literals
from builtins import str as text
import unittest

from google.cloud.forseti.common.util import rule_validator
from parameterized import parameterized
from tests.unittest_utils import ForsetiTestCase


def generate_ingress_rule():
    """Generates a minimum ingress firewall rule."""
    return {
        'allowed': [{
            'IPProtocol': u'tcp',
            'ports': [u'1-65535']
        }],
        'name':
            u'test-random-default-ingress-rule',
        'network': (u'https://www.googleapis.com/compute/v1/projects/'
                    'test-random-default-project/global/networks/'
                    'test-random-default-network'),
        'sourceRanges': [u'10.8.0.0/24']}


def generate_egress_rule():
    """Generates a minimum egress firewall rule."""
    return {
        'allowed': [{
            'IPProtocol': u'tcp',
            'ports': [u'1-65535']
        }],
        'name':
            u'test-random-default-egress-rule',
        'network': (u'https://www.googleapis.com/compute/v1/projects/'
                    'test-random-default-project/global/networks'
                    'test-random-default-network'),
        'destinationRanges': [u'10.8.0.0/24'],
        'direction': 'EGRESS'}


class RuleValidatorTest(ForsetiTestCase):
    """Multiple tests for validate_rule.validate_gcp_rule."""
    def setUp(self):
        super(ForsetiTestCase, self).setUp()

    def test_valid_ingress(self):
        """Verify valid implicit ingress rules returns None."""
        test_rule = generate_ingress_rule()
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsNone(err, 'expected no error message, got err: %s' % err)

    def test_valid_explicit_ingress(self):
        """Verify valid ingress rule with explicit direction returns None."""
        test_rule = generate_ingress_rule()
        test_rule['direction'] = 'INGRESS'
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsNone(err, 'expected no error message, got err: %s' % err)

    def test_valid_egress(self):
        """Verify valid egress rules returns None."""
        test_rule = generate_egress_rule()
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsNone(err, 'expected no error message, got err: %s' % err)

    def test_unknown_key(self):
        """A rule with an unknown key returns error."""
        test_rule = generate_ingress_rule()
        test_rule['someUnknownKey'] = True
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    @parameterized.expand([('name', 'name'), ('network', 'network')])
    def test_missing_required_key(self, test_name, key):
        """A rule missing a required key returns error."""
        test_rule = generate_ingress_rule()
        test_rule.pop(key)
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_missing_allowed_or_deny(self):
        """A rule missing either allowed returns error."""
        test_rule = generate_ingress_rule()
        test_rule.pop('allowed')
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_allowed_missing_ip_protocol(self):
        """Rule missing IPProtocol in an allow predicate returns error."""
        test_rule = generate_ingress_rule()
        test_rule['allowed'][0].pop('IPProtocol')
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_denied_missing_ip_protocol(self):
        """A rule missing IPProtocol in an denied predicate returns error."""
        test_rule = generate_ingress_rule()
        allowed = test_rule.pop('allowed')
        test_rule['denied'] = allowed
        test_rule['denied'][0].pop('IPProtocol')
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    @parameterized.expand(
        [('valid_simple', 'valid', True),
         ('valid_complex', 'va-l1d', True),
         ('invalid_long', 'x' * 64, False),
         ('invalid_capitals_at_end', 'nocapitallettersalloweD', False),
         ('invalid_number_at_start', '1-no-number-at-start', False),
         ('invalid_dash_at_start', '-no-dash-at-start', False),
         ('invalid_characters', 'underscore_not_allowed', False)])
    def test_name_validation(self, test_name, name, expected):
        """Test different name validations."""
        test_rule = generate_ingress_rule()
        test_rule['name'] = name
        err = rule_validator.validate_gcp_rule(test_rule)
        res = err is None
        self.assertEqual(
            expected, res,
            'expected %s got %s with err: %s' % (expected, res, err))

    @parameterized.expand(
        [('valid_simple', 'valid', True),
         ('valid_complex', 'va-l1d', True),
         ('invalid_long', 'x' * 64, False),
         ('invalid_capitals_at_end', 'nocapitallettersalloweD', False),
         ('invalid_number_at_start', '1-no-number-at-start', False),
         ('invalid_characters', 'underscore_not_allowed', False)])
    def test_tag_name_validation(self, test_name, tag, expected):
        """A rule with invalid tag raises InvalidFirewallRuleError."""
        test_rule = generate_ingress_rule()
        test_rule['sourceTags'] = [tag]
        err = rule_validator.validate_gcp_rule(test_rule)
        res = err is None
        self.assertEqual(
            expected, res,
            'expected %s got %s with err: %s' % (expected, res, err))

    def test_allowed_and_denied(self):
        """A rule with allow and deny ports returns error."""
        test_rule = generate_ingress_rule()
        test_rule['denied'] = [{'IPProtocol': u'udp'}]
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_no_allowed_or_denied(self):
        """A rule with no allow or deny ports returns error."""
        test_rule = generate_ingress_rule()
        test_rule.pop('allowed')
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_denied_rule(self):
        """A rule with denied ports returns None."""
        test_rule = generate_ingress_rule()
        allowed = test_rule.pop('allowed')
        test_rule['denied'] = allowed
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsNone(err, 'expected no error message, got err: %s' % err)

    def test_direction_egress_source_tag(self):
        """Rule with direction set to EGRESS + sourceTags returns error."""
        test_rule = generate_egress_rule()
        test_rule['sourceTags'] = ['tag']
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_direction_egress_source_ranges(self):
        """Rule with direction set to EGRESS + sourceRanges returns error."""
        test_rule = generate_egress_rule()
        test_rule['sourceRanges'] = ['10.8.0.0/24']
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    def test_invalid_direction(self):
        """Rule with direction set to invalid returns error."""
        test_rule = generate_ingress_rule()
        test_rule['direction'] = 'INVALID'
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    @parameterized.expand([('implicit', False), ('explicit', True)])
    def test_direction_ingress_destination_ranges(self, test_name, explicit):
        """Rule with INGRESS direction + destinationRanges returns error."""
        test_rule = generate_ingress_rule()
        if explicit:
            test_rule['direction'] = 'INGRESS'
        test_rule.pop('sourceRanges')
        test_rule['destinationRanges'] = [u'10.8.0.0/24']
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)


    def test_source_and_destination_ranges(self):
        """Rule with sourceRanges and destinationRanges returns error."""
        test_rule = generate_ingress_rule()
        test_rule['sourceRanges'] = [u'10.8.0.0/24']
        test_rule['destinationRanges'] = [u'10.8.0.0/24']
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    @parameterized.expand(
        [('negative', '-1', False),
         ('valid_zero', '0', True),
         ('valid_mid', '1000', True),
         ('valid_high', '65535', True),
         ('plusone', '65536', False),
         ('extreme', '10000000', False),
         ('not_int', 'INVALID', False)])
    def test_invalid_priority_out_of_range(self, test_name, priority, expected):
        """Rule with priority set to various values."""
        test_rule = generate_ingress_rule()
        test_rule['priority'] = priority
        err = rule_validator.validate_gcp_rule(test_rule)
        res = err is None
        self.assertEqual(
            expected, res,
            'expected %s got %s with err: %s' % (expected, res, err))

    @parameterized.expand([
        ('sourceRanges', 'sourceRanges'),
        ('sourceTags', 'sourceTags')])
    def test_ingress_keys_with_more_than_256_values(self, test_name, key):
        """Ingress rule entries with more than 256 values return error."""
        test_rule = generate_ingress_rule()
        test_rule['direction'] = 'INGRESS'
        test_rule[key] = range(257)
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

    @parameterized.expand([
        ('destinationRanges', 'destinationRanges'),
        ('targetTags', 'targetTags')])
    def test_egress_keys_with_more_than_256_values(self, test_name, key):
        """Egress rule entries with more than 256 values return error."""
        test_rule = generate_ingress_rule()
        test_rule.pop('sourceRanges')
        test_rule['direction'] = 'EGRESS'
        test_rule[key] = range(257)
        err = rule_validator.validate_gcp_rule(test_rule)
        self.assertIsInstance(err, text,
                              'expected error message, got "%s"' % err)

if __name__ == '__main__':
  unittest.main()
