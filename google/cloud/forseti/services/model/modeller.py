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

""" Modeller API. """

from google.cloud.forseti.services.model.importer import importer
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


class Modeller(object):
    """Implements the Modeller API."""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
        self.config = config

    def create_model(self, source, name, inventory_index_id, background):
        """Creates a model from the import source.

        Args:
            source (str): The source of the model, \"inventory\" or \"empty\"
            name (str): Model name to instantiate.
            inventory_index_id (int64): Inventory id to import from
            background (bool): Whether to run the model creation in background

        Returns:
            object: the created data model
        """

        LOGGER.info('Creating model: %s, inventory_index_id = %s',
                    name, inventory_index_id)

        model_manager = self.config.model_manager
        model_handle = model_manager.create(name=name)
        LOGGER.debug('Created model_handle: %s', model_handle)
        scoped_session, data_access = model_manager.get(model_handle)
        readonly_session = model_manager.get_readonly_session()

        def do_import():
            """Import runnable."""
            with scoped_session as session, readonly_session as ro_session:
                importer_cls = importer.by_source(source)
                LOGGER.debug('Importer class: %s', importer_cls)
                import_runner = importer_cls(
                    session,
                    ro_session,
                    model_manager.model(model_handle, expunge=False),
                    data_access,
                    self.config,
                    inventory_index_id)
                import_runner.run()

        if background:
            LOGGER.debug('Running importer in background.')
            self.config.run_in_background(do_import)
        else:
            LOGGER.debug('Running importer in foreground.')
            do_import()
        return model_manager.model(model_handle, expunge=True)

    def list_model(self):
        """Lists all models.

        Returns:
            list: list of Models in dao
        """

        model_manager = self.config.model_manager
        return model_manager.models()

    def get_model(self, model):
        """Get details of a model by name or handle.

        Args:
            model (str): name or handle of the model to query

        Returns:
            Model: db Model instance dao
        """

        model_manager = self.config.model_manager
        return model_manager.get_model(model)

    def delete_model(self, model_name):
        """Deletes a model.

        Args:
            model_name (str): name of the model to be deleted
        """

        LOGGER.info('Deleting model: %s', model_name)
        model_manager = self.config.model_manager
        model_manager.delete(model_name)
