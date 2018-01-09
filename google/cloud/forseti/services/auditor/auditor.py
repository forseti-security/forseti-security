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

"""Forseti Auditor."""

from Queue import Queue

from google.cloud.forseti.services.progresser import QueueProgresser
from google.cloud.forseti.auditor import rules_engine as rules_eng
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.services.auditor import storage

# pylint: disable=invalid-name,too-many-locals,broad-except

LOGGER = log_util.get_logger(__name__)


class Auditor(object):
    """Auditor."""

    def __init__(self, config):
        """Initialize.

        Args:
            config (object): The service config.
        """
        self.config = config
        storage.initialize(self.config.get_engine())

    def Run(self, config_path, model_name):
        """Run the auditor.

        Args:
            config_path (str): Path to the config.
            model_name (str): The name of the model.

        Yields:
            object: Progress objects.
        """

        try:
            config_file = file_loader.read_and_parse_file(config_path)
        except IOError:
            LOGGER.error('Unable to open Forseti Security config file. '
                         'Please check your path and filename and try again.')

        rules_path = config_file.get('auditor').get('rules_path')

        LOGGER.info('Rules path: %s', rules_path)

        progress_queue = Queue()
        progresser = QueueProgresser(progress_queue)

        def do_audit():
            """Do the audit.

            Returns:
                object: The progresser summary of run_audit().
            """

            # For each resource type, load resources from storage and
            # run the rules associated with that resource type.
            model_manager = self.config.model_manager
            scoped_session, model_data_access = model_manager.get(model_name)

            with scoped_session as session:
                return run_audit(progress_queue,
                                 session,
                                 progresser,
                                 rules_path,
                                 model_data_access,
                                 model_name)

        self.config.run_in_background(do_audit)
        for progress in iter(progress_queue.get, None):
            yield progress

    def List(self):
        """List the Audits.

        Yields:
            object: The audits found in the system.
        """

        LOGGER.info('List audits')

        with self.config.scoped_session() as session:
            auditor_data_access = storage.DataAccess(session)
            for item in auditor_data_access.list_audits():
                yield item

    def Delete(self, audit_id):
        """Delete an Audit.

        Args:
            audit_id (int): The Audit id to get results for. If None, then
                retrieve all Audit results.

        Returns:
            object: The Audit information that was deleted.
        """

        LOGGER.info('Delete audit, where audit_id=%s', audit_id)
        with self.config.scoped_session() as session:
            auditor_data_access = storage.DataAccess(session)
            return auditor_data_access.delete_audit(audit_id)

    def GetResults(self, audit_id=None):
        """Get Audit results.

        Args:
            audit_id (int): The Audit id to get results for. If None, then
                retrieve all Audit results.

        Yields:
            object: The Audit results.
        """

        LOGGER.info('List audit results, where audit_id=%s', audit_id)

        with self.config.scoped_session() as session:
            auditor_data_access = storage.DataAccess(session)
            for result in auditor_data_access.get_audit_results(audit_id):
                yield result

def run_audit(progress_queue,
              session,
              progresser,
              rules_path,
              model_data_access,
              model_handle,
              background=False):
    """Runs the audit given the environment configuration.

    Args:
        progress_queue (object): Queue to push status updates into.
        session (object): Database session.
        progresser (object): Progresser implementation to use.
        rules_path (str): The path to the rules file.
        model_data_access (object): The data access object for the model.
        model_handle (str): The model handle.
        background (bool): True if should run in background, otherwise False.

    Returns:
        object: Returns the progresser summary of the audit.

    Raises:
        Exception: Reraises any exception.
    """

    rules_engine = rules_eng.RulesEngine(rules_path)
    rules_engine.setup()

    # Get the resource types to audit, as defined in the
    # rule definitions.
    resource_types = [
        res_conf['type']
        for r in rules_engine.rules
        for res_conf in r.resource_config]

    LOGGER.info('Resource types found in rules.yaml: %s', resource_types)
    auditor_data_access = storage.DataAccess(session)

    try:
        # Create the audit entry
        new_audit = auditor_data_access.create_audit(model_handle)

        # Snapshot the rules
        try:
            rule_hash_ids = auditor_data_access.create_rule_snapshot(
                new_audit, rules_engine.rules)
            LOGGER.info('rule hash ids: %s', rule_hash_ids)
        except Exception as err:
            new_audit.set_error(session, err.message)
            LOGGER.error('%s', err, exc_info=1)
            raise

        progresser.entity_id = new_audit.id
        progresser.final_message = True if background else False
        progress_queue.put(progresser)

        for resource_type in resource_types:
            inventory_resources = model_data_access.list_resources_by_prefix(
                session, type_prefix=resource_type)

            for inv_resource in inventory_resources:
                for (audit_rule, result) in (
                        rules_engine.evaluate_rules(inv_resource)):
                    if not result:
                        continue
                    try:
                        stored_result = auditor_data_access.create_result(
                            audit_id=new_audit.id,
                            rule_id=rule_hash_ids.get(
                                audit_rule.calculate_hash()),
                            resource_type_name=inv_resource.type_name,
                            current_state={},
                            expected_state={},
                            model_handle=model_handle)
                        progresser.on_new_object(str(stored_result.id))
                    except Exception as err:
                        LOGGER.error(err)
                        progresser.on_error(err)
                        new_audit.add_warning(session, err.message)

        new_audit.complete()
    except Exception as err:
        LOGGER.error(err)
        progresser.on_error(err)
    return progresser.get_summary()
