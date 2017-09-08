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

"""Builds the inventory pipelines to run, and in the correct order to run."""

import importlib
import sys

import anytree

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import pipeline_requirements_map


LOGGER = log_util.get_logger(__name__)


class PipelineBuilder(object):
    """Inventory Pipeline Builder."""

    def __init__(self, cycle_timestamp, inventory_configs, global_configs,
                 api_map, dao_map):
        """Initialize the pipeline builder.

        Args:
            cycle_timestamp (str): Timestamp formatted as YYYYMMDDTHHMMSSZ.
            inventory_configs (dict): Inventory configurations.
            global_configs (dict): Global configurations.
            api_map (dict): GCP API info, mapped to each resource.
            dao_map (dict): DAO instances, mapped to each resource.

        Returns:
        """
        self.cycle_timestamp = cycle_timestamp
        self.inventory_configs = inventory_configs
        self.global_configs = global_configs
        self.api_map = api_map
        self.dao_map = dao_map
        self.initialized_api_map = {}

    def _get_api(self, api_name):
        """Get the api instance for the pipeline.

        The purpose is that we only want to initialize the APIs for the
        pipelines that are enabled, in order to minimize setup.

        Args:
            api_name (str): API name to get from the API map..

        Returns:
            object: Instance of the API.
        """
        api = self.initialized_api_map.get(api_name)
        if api is None:
            api_module_path = 'google.cloud.security.common.gcp_api.{}'

            try:
                api_module_name = api_module_path.format(
                    self.api_map.get(api_name).get('module_name'))
                api_module = importlib.import_module(api_module_name)
            except (AttributeError, ImportError, TypeError, ValueError) as e:
                LOGGER.error('Unable to get module %s\n%s', api_name, e)
                raise api_errors.ApiInitializationError(e)

            api_class_name = (
                self.api_map.get(api_name).get('class_name'))
            try:
                api_class = getattr(api_module, api_class_name)
            except AttributeError as e:
                LOGGER.error('Unable to instantiate %s\n%s',
                             api_class_name, sys.exc_info()[0])
                raise api_errors.ApiInitializationError(e)

            api_version = self.api_map.get(api_name).get('version')
            try:
                if api_version is None:
                    api = api_class(self.global_configs)
                else:
                    api = api_class(self.global_configs,
                                    version=api_version)
            except api_errors.ApiInitializationError as e:
                LOGGER.error('Failed to initialize API %s, v=%s\n%s',
                             api_class_name, api_version, e)
                raise api_errors.ApiInitializationError(api_class_name, e)

            self.initialized_api_map[api_name] = api

        return api

    def _find_runnable_pipelines(self, root):
        """Find the enabled pipelines to run.

        Args:
            root (PipelineNode): Represents the top-level starting point
                of the pipeline dependency tree. The entire pipeline
                dependency tree are tuple of children PipelineNodes
                of this root.

                Example:
                root.resource_name = 'organizations'
                root.enabled = True
                root.parent = None
                root.children = (pipeline_node1, pipeline_node2, ...)

        Returns:
            list: List of the pipelines that will be run. The
                order in the list represents the order they need to be run.
                i.e. going top-down in the dependency tree.
        """
        # If child pipeline is true, then all parents will become true.
        # Even if the parent(s) is(are) false.
        # Manually traverse the parents since anytree walker api doesn't
        # make sense.
        for node in anytree.iterators.PostOrderIter(root):
            if node.enabled:
                while node.parent is not None:
                    node.parent.enabled = node.enabled
                    node = node.parent

        LOGGER.debug('Dependency tree of the pipelines: %s',
                     anytree.RenderTree(root, style=anytree.AsciiStyle())
                     .by_attr('resource_name'))
        LOGGER.debug('Which pipelines are enabled: %s',
                     anytree.RenderTree(root, style=anytree.AsciiStyle())
                     .by_attr('enabled'))

        # Now, we have the true state of whether a pipeline should be run.
        # Get a list of pipeline instances that will actually be run.
        # The order matters: must go top-down in the tree, by PreOrder.
        # http://anytree.readthedocs.io/en/latest/apidoc/anytree.iterators.html
        runnable_pipelines = []
        for node in anytree.iterators.PreOrderIter(root):
            if node.enabled:
                module_path = 'google.cloud.security.inventory.pipelines.{}'
                module_name = module_path.format(
                    pipeline_requirements_map.REQUIREMENTS_MAP
                    .get(node.resource_name)
                    .get('module_name'))
                try:
                    module = importlib.import_module(module_name)
                except (ImportError, TypeError, ValueError) as e:
                    LOGGER.error('Unable to import %s\n%s', module_name, e)
                    continue

                # Convert module naming to class naming.
                # Module naming is "this_is_foo"
                # Class naming is "ThisIsFoo"
                class_name = (
                    pipeline_requirements_map.REQUIREMENTS_MAP
                    .get(node.resource_name)
                    .get('module_name')
                    .title()
                    .replace('_', ''))
                try:
                    pipeline_class = getattr(module, class_name)
                except AttributeError:
                    LOGGER.error('Unable to instantiate %s\n%s',
                                 class_name, sys.exc_info()[0])
                    continue

                api_name = (pipeline_requirements_map.REQUIREMENTS_MAP
                            .get(node.resource_name)
                            .get('api_name'))
                try:
                    api = self._get_api(api_name)
                except api_errors.ApiInitializationError:
                    continue

                dao = self.dao_map.get(
                    pipeline_requirements_map.REQUIREMENTS_MAP
                    .get(node.resource_name)
                    .get('dao_name'))
                if dao is None:
                    LOGGER.error('Unable to find dao for %s',
                                 node.resource_name)
                    continue

                pipeline = pipeline_class(
                    self.cycle_timestamp, self.global_configs, api, dao)
                runnable_pipelines.append(pipeline)

        return runnable_pipelines

    def _build_dependency_tree(self):
        """Build the dependency tree with all the pipeline nodes.

        Returns:
            PipelineNode: Represents the top-level starting point
                of the pipeline dependency tree. The entire pipeline
                dependency tree are children of this root.

                Example:
                root.resource_name = 'organizations'
                root.enabled = True
                root.parent = None
                root.children = (pipeline_node1, pipeline_node2, ...)
        """
        # First pass: map all the pipelines to their own nodes,
        # regardless if they should run or not.
        map_of_all_pipeline_nodes = {}

        configured_pipelines = self.inventory_configs.get('pipelines', [])

        for entry in configured_pipelines:
            map_of_all_pipeline_nodes[entry.get('resource')] = PipelineNode(
                entry.get('resource'), entry.get('enabled'))

        # Another pass: build the dependency tree by setting the parents
        # correctly on all the nodes.
        for entry in configured_pipelines:
            parent_name = (
                pipeline_requirements_map.REQUIREMENTS_MAP.get(
                    entry.get('resource'), {}).get('depends_on'))
            if parent_name is not None:
                parent_node = map_of_all_pipeline_nodes[parent_name]
                map_of_all_pipeline_nodes[entry.get('resource')].parent = (
                    parent_node)

        # Assume root is organizations.
        return map_of_all_pipeline_nodes.get('organizations')

    def build(self):
        """Build the pipelines to load data.

        Returns:
            list: List of pipelines instances that will be run.
        """
        root = self._build_dependency_tree()

        return self._find_runnable_pipelines(root)


class PipelineNode(anytree.node.NodeMixin):
    """A custom anytree node with pipeline attributes.

    More info at anytree's documentation.
    http://anytree.readthedocs.io/en/latest/apidoc/anytree.node.html
    """

    def __init__(self, resource_name, enabled, parent=None):
        """Initialize the pipeline node.

        Args:
            resource_name (str): Name of the resource.
            enabled (bool): Whether the pipeline should run.
            parent (PipelineNode): This node's parent.

        Returns:
        """
        self.resource_name = resource_name
        self.enabled = enabled
        self.parent = parent
