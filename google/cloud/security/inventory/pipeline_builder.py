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

import anytree

from google.cloud.security.common.gcp_api import admin_directory as ad
from google.cloud.security.common.gcp_api import bigquery as bq
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.gcp_api import storage as gcs
from google.cloud.security.common.gcp_api import cloudsql
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import file_loader


class PipelineBuilder(object):

    RESOURCE_REQUIREMENTS_MAP = {
        'bigquery_datasets': 
            {'module_name': 'load_bigquery_datasets_pipeline',
             'api_name': 'bigquery_api',
             'dao_name': 'dao'},
        'buckets': 
            {'module_name': 'load_projects_buckets_pipeline',
             'api_name': 'gcs_api',
             'dao_name': 'project_dao'},
        'buckets_acls': 
            {'module_name': 'load_projects_buckets_acls_pipeline',
             'api_name': 'gcs_api',
             'dao_name': 'bucket_dao'},
        'cloudsql': 
            {'module_name': 'load_projects_cloudsql_pipeline',
             'api_name': 'cloudsql_api',
             'dao_name': 'cloudsql_dao'},
        'firewall_rules': 
            {'module_name': 'load_firewall_rules_pipeline',
             'api_name': 'compute_beta_api',
             'dao_name': 'project_dao'},
        'folders':
            {'module_name': 'load_folders_pipeline',
             'api_name': 'crm_v2beta1_api',
             'dao_name': 'dao'},
        'forwarding_rules': 
            {'module_name': 'load_forwarding_rules_pipeline',
             'api_name': 'compute_api',
             'dao_name': 'forwarding_rules_dao'},
        'group_members':
            {'module_name': 'load_group_members_pipeline',
             'api_name': 'admin_api',
             'dao_name': 'dao'},
        'groups':
            {'module_name': 'load_groups_pipeline',
             'api_name': 'admin_api',
             'dao_name': 'dao'},
        'org_iam_policies':
            {'module_name': 'load_org_iam_policies_pipeline',
             'api_name': 'crm_api',
             'dao_name': 'organization_dao'},
        'organizations': 
            {'module_name': 'load_orgs_pipeline',
             'api_name': 'crm_api',
             'dao_name': 'organization_dao'},
        'projects':
            {'module_name': 'load_projects_pipeline',
             'api_name': 'crm_api',
             'dao_name': 'project_dao'},
        'projects_iam_policies':
            {'module_name': 'load_projects_iam_policies_pipeline',
             'api_name': 'crm_api',
             'dao_name': 'project_dao'},
    }

    def __init__(self, cycle_timestamp, pipeline_configs, flag_configs,
                 api_map, dao_map):
        self.cycle_timestamp = cycle_timestamp
        self.pipeline_configs = file_loader.read_and_parse_file(
            pipeline_configs)
        self.flag_configs = flag_configs
        self.api_map = api_map
        self.dao_map = dao_map

    def build(self, **kwargs):
        """Build the pipelines to load data.
    
        Args:
            cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            configs: Dictionary of configurations.
            kwargs: Extra configs.
    
        Returns:
            List of pipelines that will be run.
    
        Raises: inventory_errors.LoadDataPipelineError.
        """
  
        # first pass: map all the pipelines to their own nodes,
        # regardless if they should run or not
        map_of_all_pipeline_nodes = {}
        for i in self.pipeline_configs:
            map_of_all_pipeline_nodes[i.get('resource')] = PipelineNode(
                i.get('resource'), i.get('should_run'))
    
        # another pass: build the dependency tree by setting the parents
        # correctly on all the nodes
        for i in self.pipeline_configs:
            parent_name = i.get('depends_on')
            if parent_name is not None:
                parent_node = map_of_all_pipeline_nodes[parent_name]
                map_of_all_pipeline_nodes[i.get('resource')].parent = parent_node
    
        root = map_of_all_pipeline_nodes.get('organizations')
    
        # If child pipeline is true, then all parents will become true.
        # Even if the parent(s) is(are) false.
        # Manually traverse the parents since anytree walker api doesn't make sense.
        for node in anytree.iterators.PostOrderIter(root):
            if node.should_run:
                while node.parent is not None:
                    node.parent.should_run = node.should_run
                    node = node.parent
    
        print anytree.RenderTree(root, style=anytree.AsciiStyle()).by_attr('resource_name')
        print anytree.RenderTree(root, style=anytree.AsciiStyle()).by_attr('should_run')
    
        # Now, we have the true state of whether a pipeline should be run or not.
        # Get a list of pipeline instances that will actually be run.
        # The order matters: must go top-down in the tree.  Run the piplelines
        # in each level before running the pipelines in the next level.
        pipelines_to_run = []
        for node in anytree.iterators.PreOrderIter(root):
            if node.should_run:
                module_path = 'google.cloud.security.inventory.pipelines.{}'
                module_name = module_path.format(
                    self.RESOURCE_REQUIREMENTS_MAP
                        .get(node.resource_name)
                        .get('module_name'))
                module = importlib.import_module(module_name)
                class_name = (
                    self.RESOURCE_REQUIREMENTS_MAP
                        .get(node.resource_name)
                        .get('module_name')
                        .title()
                        .replace('_', ''))
                pipeline_class = getattr(module, class_name)
                pipelines_to_run.append(
                    pipeline_class(
                        self.cycle_timestamp,
                        self.flag_configs,
                        self.api_map.get(
                            self.RESOURCE_REQUIREMENTS_MAP
                                .get(node.resource_name)
                                .get('api_name')),
                        self.dao_map.get(
                            self.RESOURCE_REQUIREMENTS_MAP
                                .get(node.resource_name)
                                .get('dao_name')),
                    )
                )

        return pipelines_to_run


class PipelineNode(anytree.node.NodeMixin):
    """A custom anytree node with pipeline attributes."""

    def __init__(self, resource_name, should_run, parent=None):
        self.resource_name = resource_name
        self.should_run = should_run
        self.parent = parent
