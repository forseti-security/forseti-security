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

from google.cloud.forseti import config
from google.cloud.forseti.auditor import rules_engine as rules_eng
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.services.auditor import dao


LOGGER = log_util.get_logger(__name__)


class AuditorRunner(object):
    """AuditorRunner."""

    def __init__(self, config_props=None):
        self.config = config_props or config.FORSETI_CONFIG.root_config.auditor

    def run(self):
        rules_engine = rules_eng.RulesEngine(self.config.rules_path)
        rules_engine.setup()
        resource_types = [
            res_conf['type'] 
            for r in rules_engine.rules
            for res_conf in r.resource_config]

        LOGGER.info('Resource types found: %s', resource_types)

        # For each resource type, load all the resources from the database.
        # TODO: Create a mapping between the gcp_type and the dao
        # and call each dao's get_all() method.
        all_results = []
        for resource_type in resource_types:
            loaded_resources = None
            try:
                loaded_resources = resource_util.load_all(resource_type)
            except Exception as err:
                LOGGER.warn(
                    'Unable to load resources for %s due to %s',
                    resource_type, err)

            if not loaded_resources:
                continue

            for resource in loaded_resources:
                all_results.extend([
                    result
                    for result in rules_engine.evaluate_rules(resource)
                    if result.result])

            LOGGER.info('%s rules evaluated to True', len(all_results))
        return all_results


def Run(config_path, model_name):
    if not config.FORSETI_CONFIG:
        if not config_path:
            LOGGER.error('Provide a --config to run the Auditor.')
            return 1
        config.FORSETI_CONFIG = config.from_file(config_path)

    log_util.set_logger_level_from_config(
        config.FORSETI_CONFIG.root_config.auditor.get('loglevel'))

    runner = AuditorRunner()
    runner.run()

    return 0

def List(config_path, model_name):
    if not config.FORSETI_CONFIG:
        if not config_path:
            LOGGER.error('Provide a --forseti-config file to run the Auditor.')
            return 1
        config.FORSETI_CONFIG = config.from_file(config_path)

    log_util.set_logger_level_from_config(
        config.FORSETI_CONFIG.root_config.auditor.get('loglevel'))

    audits = dao.list_audits()

    return 0


def main(_):
    return run()


if __name__ == '__main__':
    app.run()
