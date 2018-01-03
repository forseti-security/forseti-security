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

from google.apputils import app

from google.cloud.forseti.auditor import rules_engine as rules_eng
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.services.auditor import storage


LOGGER = log_util.get_logger(__name__)


class Auditor(object):
    """Auditor."""

    def __init__(self, config):
        self.config = config

    def _check_config(self):
        """Check configuration."""

        # TODO: fix this
        if not self.config.FORSETI_CONFIG:
            if not config_path:
                LOGGER.error('Provide a --config to run Auditor services.')
                return 1
            config.FORSETI_CONFIG = config.from_file(config_path)

        log_util.set_logger_level_from_config(
            config.FORSETI_CONFIG.root_config.auditor.get('loglevel'))

    def Run(self, config_path, model_name):
        """Run the auditor.

        Args:
            config_path (str): Path to the config.
            model_name (str): The name of the model.
        """

        try:
            config_file = file_loader.read_and_parse_file(config_path)
        except IOError:
            LOGGER.error('Unable to open Forseti Security config file. '
                         'Please check your path and filename and try again.')

        rules_path = config_file.get('auditor').get('rules_path')

        LOGGER.info('Rules path: %s' % rules_path)
        rules_engine = rules_eng.RulesEngine(rules_path)
        rules_engine.setup()

        # Get the resource types to audit, as defined in the
        # rule definitions.
        resource_types = [
            res_conf['type'] 
            for r in rules_engine.rules
            for res_conf in r.resource_config]

        LOGGER.info('Resource types found in rules.yaml: %s', resource_types)

        # For each resource type, load resources from storage and
        # run the rules associated with that resource type.
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)

        with scoped_session as session:
            all_results = []
            for resource_type in resource_types:
                loaded_resources = data_access.list_resources_by_prefix(
                    session, type_prefix=resource_type)

                for resource in loaded_resources:
                    all_results.extend([
                        result
                        for result in rules_engine.evaluate_rules(resource)
                        if result.result])

                LOGGER.info('%s rules evaluated to True', len(all_results))

            # TODO: store all_results in results table instead of in a list
            print all_results

        return 0

    def List(self):
        """List the Audits."""

        with self.config.scoped_session() as session:
            for item in DataAccess.list(session):
                yield item


def main(_):
    return Auditor().run()


if __name__ == '__main__':
    app.run()
