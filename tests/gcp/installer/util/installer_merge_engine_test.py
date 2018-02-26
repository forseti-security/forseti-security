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

"""Tests for setup/gcp/installer/util/merge_engine.py."""

import unittest

import setup.gcp.installer.util.merge_engine as merge_engine

from tests.unittest_utils import ForsetiTestCase


class MergeEngineModuleTest(ForsetiTestCase):

    def test_merge_object_flat(self):
        """Test merge flat dictionary."""
        merge_to = {'a': 'aval', 'b': 'bval', 'c': 'cval'}
        merge_from = {'a': 'aval2', 'c': 'cval2'}
        expected_dict = {'a': 'aval2', 'b': 'bval', 'c': 'cval2'}

        merge_engine.merge_object(merge_from, merge_to)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_flat_target_with_extra_vals(self):
        """Test merge flat dictionary."""
        merge_to = {'a': 'aval', 'b': 'bval', 'c': 'cval'}
        merge_from = {'a': 'aval2', 'c': 'cval2', 'd': 'dval2'}
        expected_dict = {'a': 'aval2', 'b': 'bval', 'c': 'cval2', 'd': 'dval2'}

        merge_engine.merge_object(merge_from, merge_to)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_flat_with_fields_to_ignore(self):
        """Test merge flat dictionary."""
        merge_to = {'a': 'aval', 'b': 'bval', 'c': 'cval'}
        merge_from = {'a': 'aval2', 'b': 'bval2', 'c': 'cval2'}
        expected_dict = {'a': 'aval', 'b': 'bval2', 'c': 'cval'}
        fields_to_ignore = ['a', 'c']

        merge_engine.merge_object(merge_from, merge_to, fields_to_ignore)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_flat_with_fields_to_ignore_target_with_extra_vals(self):
        """Test merge flat dictionary."""
        merge_to = {'a': 'aval', 'b': 'bval', 'c': 'cval'}
        merge_from = {'a': 'aval2', 'b': 'bval2', 'c': 'cval2', 'd': 'dval2'}
        expected_dict = {'a': 'aval', 'b': 'bval2', 'c': 'cval', 'd': 'dval2'}
        fields_to_ignore = ['a', 'c']

        merge_engine.merge_object(merge_from, merge_to, fields_to_ignore)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_nested(self):
        """Test merge flat dictionary."""
        merge_to = {'a0': {'a1': {'a2': 'aval'}},
                      'b0': {'b1': {'b2': 'bval'}},
                      'c0': {'c1': {'c2': 'cval'}}}
        merge_from = {'a0': {'a1': {'a2': 'aval2'}},
                       'c0': {'c1': {'c2': 'cval2'}}}

        expected_dict = {'a0': {'a1': {'a2': 'aval2'}},
                         'b0': {'b1': {'b2': 'bval'}},
                         'c0': {'c1': {'c2': 'cval2'}}}

        merge_engine.merge_object(merge_from, merge_to)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_nested_target_with_extra_vals(self):
        """Test merge flat dictionary."""
        merge_to = {'a0': {'a1': {'a2': 'aval'}},
                      'b0': {'b1': {'b2': 'bval'}},
                      'c0': {'c1': {'c2': 'cval'}}}
        merge_from = {'a0': {'a1': {'a2': 'aval2'}},
                       'c0': {'c1': {'c2': 'cval2'}},
                       'd0': {'d1': 'dval2'}}

        expected_dict = {'a0': {'a1': {'a2': 'aval2'}},
                         'b0': {'b1': {'b2': 'bval'}},
                         'c0': {'c1': {'c2': 'cval2'}},
                         'd0': {'d1': 'dval2'}}

        merge_engine.merge_object(merge_from, merge_to)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_nested_target_with_extra_vals_nested(self):
        """Test merge flat dictionary."""
        merge_to = {'a0': {'a1': {'a2': 'aval'}},
                      'b0': {'b1': {'b2': 'bval'}},
                      'c0': {'c1': {'c2': 'cval'}}}
        merge_from = {'a0': {'a1': {'a2': 'aval2'}},
                       'c0': {'c1': {'c2': 'cval2'},
                              'c12': 'cval12'}}

        expected_dict = {'a0': {'a1': {'a2': 'aval2'}},
                         'b0': {'b1': {'b2': 'bval'}},
                         'c0': {'c1': {'c2': 'cval2'},
                                'c12': 'cval12'}}

        merge_engine.merge_object(merge_from, merge_to)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_nested_fields_to_ignore(self):
        """Test merge flat dictionary."""
        merge_to = {'a0': {'a1': {'a2': 'aval'}},
                      'b0': {'b1': {'b2': 'bval'}},
                      'c0': {'c1': {'c2': 'cval'}}}
        merge_from = {'a0': {'a1': {'a2': 'aval2'}},
                       'b0': {'b1': {'b2': 'cval2'}},
                       'c0': {'c1': {'c2': 'cval2'}}}

        fields_to_ignore = ['b0', 'a2']

        expected_dict = {'a0': {'a1': {'a2': 'aval'}},
                         'b0': {'b1': {'b2': 'bval'}},
                         'c0': {'c1': {'c2': 'cval2'}}}

        merge_engine.merge_object(merge_from, merge_to, fields_to_ignore)

        self.assertEqual(expected_dict, merge_to)

    def test_merge_object_nested_list_with_field_identifiers(self):
        """Test merge flat dictionary."""
        merge_to = {'a0': {'a1': [
            {'name': 'a21', 'val': 'a21_val'},
            {'name': 'a22', 'val': 'a22_val'},
            {'name': 'a23', 'val': 'a23_val'},
        ]}}
        merge_from = {'a0': {'a1': [
            {'name': 'a21', 'val': 'a21_val_target'}
        ]}}
        expected_dict ={'a0': {'a1': [
            {'name': 'a21', 'val': 'a21_val_target'},
            {'name': 'a22', 'val': 'a22_val'},
            {'name': 'a23', 'val': 'a23_val'},
        ]}}

        fields_to_ignore = []
        field_identifiers = {'a1': 'name'}

        merge_engine.merge_object(merge_from, merge_to,
                         fields_to_ignore, field_identifiers)

        self.assertEqual(expected_dict, merge_to)

if __name__ == '__main__':
    unittest.main()
