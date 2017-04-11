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

"""Tests the CSV Writer."""

from google.apputils import basetest
import mock

from google.cloud.security.common.data_access import csv_writer


class CsvWriterTest(basetest.TestCase):
    """Tests for the CSV Writer."""

    @mock.patch.object(csv_writer, 'os')
    @mock.patch.object(csv_writer.csv, 'DictWriter')
    @mock.patch.object(csv_writer.tempfile, 'NamedTemporaryFile')
    def test_csv_file_is_removed(self, mock_tempfile,
                                 mock_dict_writer, mock_os):
        """Test that the csv file is removed."""
        csv_writer.CSV_FIELDNAME_MAP = mock.MagicMock()
        with csv_writer.write_csv('foo', mock.MagicMock()) as csv_file:
            csv_filename = csv_file.name

        mock_os.remove.assert_called_once_with(csv_filename)

        # Test that the csv file is still removed on error."""
        mock_dict_writer.return_value = IOError

        with csv_writer.write_csv('foo', mock.MagicMock()) as csv_file:
            csv_filename = csv_file.name

        self.assertEquals(2, mock_os.remove.call_count)
        called_args, called_kwargs = mock_os.remove.call_args_list[1]
        self.assertEquals(csv_filename, called_args[0])
        
        
if __name__ == '__main__':
    basetest.main()
