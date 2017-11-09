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

"""Tests the pipeline requirements map."""

import importlib
import inspect
import pkgutil
import unittest

from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.inventory import pipeline_requirements_map
from google.cloud.forseti.inventory.pipelines import base_pipeline


class PipelineRequirementsMapTest(ForsetiTestCase):
    """Tests for the pipeline requirements map test."""

    def _get_all_pipeline_module_names(self):
        """Get all the name of the modules that are pipelines.

        Returns: List of valid pipeline module names.
        """
        pipeline_path = 'google/cloud/forseti/inventory/pipelines'
        pipeline_module_names = []
        for _, module_name, _ in pkgutil.iter_modules([pipeline_path]):
            try:
                module = importlib.import_module(
                    'google.cloud.forseti.inventory.pipelines.{0}'.format(
                        module_name))
                for filename in dir(module):
                    obj = getattr(module, filename)

                    if (inspect.isclass(obj) and
                        issubclass(obj, base_pipeline.BasePipeline) and
                        obj is not base_pipeline.BasePipeline):
                            pipeline_module_names.append(module_name)
            except ImportError:
                continue

        return pipeline_module_names

    def _get_all_mapped_module_names(self):
        """Get all the name of the pipeline modules that have been mapped.

        Returns: List of mapped pipeline module names.
        """
        mapped_module_names = []
        for requirements in pipeline_requirements_map.REQUIREMENTS_MAP.values():
            mapped_module_names.append(requirements.get('module_name'))

        return mapped_module_names

    def testInventoryPipelinesAndRequirementsMapAreInSync(self):
        mapped_module_names = self._get_all_mapped_module_names()
        pipeline_module_names = self._get_all_pipeline_module_names()

        self.assertItemsEqual(mapped_module_names, pipeline_module_names)


if __name__ == '__main__':
      unittest.main()
