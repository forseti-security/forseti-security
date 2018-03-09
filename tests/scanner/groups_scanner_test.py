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

"""Scanner runner script test."""

import pickle
import mock

import anytree
import unittest
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import groups_scanner
from tests.scanner.test_data import fake_groups_scanner_data as fake_data


class GroupsScannerTest(ForsetiTestCase):

    def _pickle_dump(self, obj, filename):
        """Dump object to pickle file.

        Args:
            obj: Any object to be pickled.
            filename: String of the pickle filename.

        Returns:
             None
        """
        pickle.dump(obj, open('tests/scanner/test_data/' + filename, 'wb'))

    def _pickle_load(self, filename):
        """Loads a pickle file.

        Args:
            filename: String of the pickle filename to load.

        Returns:
            The object that was pickled.
        """
        return pickle.load(open('tests/scanner/test_data/' + filename, 'rb'))

    def _render_ascii(self, starting_node, attr):
        """Render an ascii representation of the tree structure.

        Args:
            starting_node: The starting node to render the ascii.

        Returns:
            attr: String of the attribute to render.
        """
        return anytree.RenderTree(
            starting_node,
            style=anytree.AsciiStyle()).by_attr(attr)

    def setUp(self):
        pass


if __name__ == '__main__':
    unittest.main()
