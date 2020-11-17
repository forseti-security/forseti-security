# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

"""Notifier inventory summary export tests"""

import pytest
import re
import subprocess


class TestNotifierInventorySummaryExport:
    """Tests for the notifier inventory summary export feature."""

    @pytest.mark.e2e
    @pytest.mark.notifier
    @pytest.mark.server
    def test_inventory_summary_export_gcs(
            self,
            forseti_notifier_readonly: subprocess.CompletedProcess,
            forseti_server_bucket_name: str):
        """Test that the inventory summary is exported to GCS.

        Args:
            forseti_notifier_readonly (subprocess.CompletedProcess): Notifier
            run process result.
            forseti_server_bucket_name (str): Forseti server bucket name.
        """
        match = re.search(
            fr'gs://{forseti_server_bucket_name}/inventory_summary/(.*).csv',
            str(forseti_notifier_readonly.stdout))
        assert match
        gcs_path = match.group(0)

        cmd = ['sudo', 'gsutil', 'ls', gcs_path]
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)

        assert result.returncode == 0
