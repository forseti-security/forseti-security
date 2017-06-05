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

"""Builds the inventory pipelines to run, and in the correct order to run."""

import importlib
import sys

import anytree

from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import pipeline_requirements_map


LOGGER = log_util.get_logger(__name__)


class PipelineBuilder(object):
    """Inventory Pipeline Builder."""

    def __init__(self, cycle_timestamp, config_path, flags,
                 api_map, dao_map):
        """Initialize the pipeline builder.

        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            config_path: String of the path to the inventory config file.
            flags: Dictionary of flag values.
            api_map: Dictionary of GCP API instances, mapped to each resource.
            dao_map: Dictionary of DAO instances, mapped to each resource.

        Returns:
            None
        """
        self.cycle_timestamp = cycle_timestamp
        self.config_path = config_path
        self.flags = flags
        self.api_map = api_map
        self.dao_map = dao_map

    def _find_runnable_pipelines(self, root):
        """Initialize the pipeline builder.

        Args:
            root: PipelineNode representing the top-level starting point
                of the pipeline dependency tree. The entire pipeline
                dependency tree are tuple of children PipelineNodes
                of this root.

                Example:
                root.resource_name = 'organizations'
                root.enabled = True
                root.parent = None
                root.children = (pipeline_node1, pipeline_node2, ...)

        Returns:
            runnable_pipelines: List of the pipelines that will be run. The
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

                api = self.api_map.get(
                    pipeline_requirements_map.REQUIREMENTS_MAP
                    .get(node.resource_name)
                    .get('api_name'))
                if api is None:
                    LOGGER.error('Unable to find api for %s',
                                 node.resource_name)
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
                    self.cycle_timestamp, self.flags, api, dao)
                runnable_pipelines.append(pipeline)

        return runnable_pipelines

    def _build_dependency_tree(self):
        """Build the dependency tree with all the pipeline nodes.

        Returns:
            PipelineNode representing the top-level starting point
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
        config = file_loader.read_and_parse_file(self.config_path)
        for entry in config.get('resources', []):
            map_of_all_pipeline_nodes[entry.get('resource')] = PipelineNode(
                entry.get('resource'), entry.get('enabled'))

        # Another pass: build the dependency tree by setting the parents
        # correctly on all the nodes.
        for entry in config.get('resources', []):
            parent_name = (
                pipeline_requirements_map.REQUIREMENTS_MAP.get(
                    entry.get('resource')).get('depends_on'))
            if parent_name is not None:
                parent_node = map_of_all_pipeline_nodes[parent_name]
                map_of_all_pipeline_nodes[entry.get('resource')].parent = (
                    parent_node)

        # Assume root is organizations.
        return map_of_all_pipeline_nodes.get('organizations')

    def build(self):
        """Build the pipelines to load data.

        Returns:
            List of pipelines instances that will be run.
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
            resource_name: String of name of the resource.
            enabled: Boolean whether the pipeline should run.
            parent: PipelineNode of this node's parent.

        Returns:
            None
        """
        self.resource_name = resource_name
        self.enabled = enabled
        self.parent = parent
