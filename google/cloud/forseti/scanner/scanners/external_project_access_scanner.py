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

"""External project access scanner."""

# pylint: disable=line-too-long

import time

from google.auth.exceptions import RefreshError
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.gcp_api.errors import ApiExecutionError
from google.cloud.forseti.common.gcp_api import api_helpers # noqa=E501
from google.cloud.forseti.common.gcp_type import resource_util # noqa=E501
from google.cloud.forseti.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient # noqa=E501
from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.inventory.storage import Storage
from google.cloud.forseti.scanner.audit import external_project_access_rules_engine as epa_rules_engine # noqa=E501
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)

SCOPES = ['https://www.googleapis.com/auth/cloudplatformprojects.readonly']


def _get_inventory_storage(session, inventory_index_id):
    """Creates an open inventory.

    Args:
        session (object): db session.
        inventory_index_id (int): The inventory index
    Returns:
        Storage: storage object
    """
    inventory_storage = Storage(session, inventory_index_id, True)
    inventory_storage.open()
    return inventory_storage


def get_user_emails(service_config, member_types=None):
    """Retrieves the list of user email addresses from inventory.

    Args:
        service_config (dict): The service configuration
        member_types (list): Member types to query in storage. This
            defaults to 'gsuite_user'.

    Returns:
        list: List of list of user e-mail addresses.
    """
    if not member_types:
        member_types = ['gsuite_user']

    emails = []
    with service_config.scoped_session() as session:
        inventory_index_id = (
            DataAccess.get_latest_inventory_index_id(session))
        inventory_storage = _get_inventory_storage(session,
                                                   inventory_index_id)
        for inventory_row in inventory_storage.iter(type_list=member_types):
            emails.append(inventory_row.get_resource_data()['primaryEmail'])

    return emails


def extract_project_ids(crm_client):
    """Extract a list of project ID's

    Args:
        crm_client (CloudResourceManagerClient):
            An authenticated CRM client

    Returns:
        list: Project ID's as strings
    """

    project_response = crm_client.get_projects()

    projects = api_helpers.flatten_list_results(project_response, 'projects')
    return [project['projectId'] for project in projects]


def memoize_ancestry(ancestry_function):
    # pylint: disable=C0301
    """A decorator function to intelligently retrieve project ancestries, only if necessary.

    Args:
        ancestry_function (function): The ancestry
            retrieval function.

    Returns:
        function: The helper
    """
    discovered_ancestries = {}
    # pylint: disable=W9011,W9012,C0111

    def helper(crm_client, project_id):
        if project_id not in discovered_ancestries:
            discovered_ancestries[project_id] = (
                ancestry_function(crm_client, project_id))
        return discovered_ancestries[project_id]
    return helper


@memoize_ancestry
def get_project_ancestry(crm_client, project_id):
    """Get project ancestry as a list of type Resource.

    Args:
        crm_client (CloudResourceManagerClient):
            crm client
        project_id (str): A project ID

    Returns:
        list: Resource objects defining the ancestry
            chain from the Project to the Organization
    """

    ancestries = crm_client.get_project_ancestry(project_id)
    ancestry_resources = (
        resource_util.cast_to_gcp_resources(ancestries))

    return ancestry_resources


def get_project_ancestries(crm_client, project_id_list):
    """Get the ancestries from a list of project ID's

    Args:
        crm_client (CloudResourceManagerClient):
            crm client
        project_id_list (list): A list of project ID's
            as strings

    Returns:
        list: A list of lists ofResource objects
            defining the ancestrychain from the Project
            to the Organization
    """
    ancestry_list = []
    for project_id in project_id_list:
        ancestry_list.append(get_project_ancestry(crm_client,
                                                  project_id))
    return ancestry_list


class ExternalProjectAccessScanner(base_scanner.BaseScanner):
    """Scanner for external project access."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(ExternalProjectAccessScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.inventory_configs = self.service_config.get_inventory_config()
        self.rules_engine = (
            epa_rules_engine.ExternalProjectAccessRulesEngine(
                rules_file_path=self.rules,
                snapshot_timestamp=self.snapshot_timestamp))
        self.rules_engine.build_rule_book(self.inventory_configs)
        self._ancestries = dict()

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): A list of violations.
        """
        all_violations = self._flatten_violations(all_violations)

        self._output_results_to_db(all_violations)

    def _find_violations(self, ancestries_by_user):
        """Find violations in the policies.

        Args:
            ancestries_by_user (dict): The project ancestries collected
                                               from the scanner
        Returns:
            list: A list of ExternalProjectAccess violations
        """
        all_violations = []
        LOGGER.info('Finding project access violations...')

        for user_mail, project_ancestries in ancestries_by_user.iteritems():
            for project_ancestry in project_ancestries:
                violations = (
                    self.rules_engine.find_violations(
                        user_mail, project_ancestry))
                all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            rule_ancestors_names = []

            for ancestor in violation.rule_ancestors:
                rule_ancestors_names.append(ancestor.name)

            violation_data = {
                'full_name': violation.full_name,
                'member': violation.member,
                'rule_ancestors': rule_ancestors_names
            }

            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'resource_data': violation.resource_data
            }

    def _get_crm_client(self, user_email):
        """Get a user scoped CloudResourceManagerClient.

        Args:
            user_email (str): The e-mail address of the
                user.

        Returns:
            CloudResourceManagerClient: crm client
        """
        user_scoped_credential = (
            api_helpers.get_delegated_credential(user_email, SCOPES))

        client = CloudResourceManagerClient(
            global_configs=self.inventory_configs,
            credentials=user_scoped_credential)

        return client

    def _retrieve(self):
        """Retrieve the project ancestries for all users.

        Returns:
            dict: User project relationship.
            {"user1@example.com": [[Project("1234"), Organization("1234567")],
                                  [Project("12345"), Folder("ABCDEFG"),
                                  Organization("1234567")]],
             "user2@example.com": [[Project("1234"), Organization("34567")],
                                  [Project("12345"), Folder("ABCDEFG"),
                                  Organization("1234567")]]}
        """
        # This dictionary is the result of the scan.  The key
        # is the user ID.  The value is a list of lists of ancestries.
        user_to_project_ancestries_map = {}
        user_count = 0

        start_time = time.time()

        user_emails = get_user_emails(self.service_config)

        for user_email in user_emails:
            user_count += 1
            try:
                user_crm_client = self._get_crm_client(user_email)

                project_ids = extract_project_ids(user_crm_client)
                ancestries = get_project_ancestries(user_crm_client,
                                                    project_ids)

                user_to_project_ancestries_map[user_email] = ancestries
            except (RefreshError, ApiExecutionError):
                LOGGER.debug('Unable to access project ancestry %s.',
                             user_email)

        # TODO: Remove when instrumentation is implemented.
        elapsed_time = time.time() - start_time

        LOGGER.debug('It took %f seconds to query projects for %d users',
                     elapsed_time,
                     user_count)

        return user_to_project_ancestries_map

    def run(self):
        """Entry point to run the scanner."""
        user_to_project_ancestries_map = self._retrieve()
        all_violations = self._find_violations(user_to_project_ancestries_map)
        self._output_results(all_violations)
