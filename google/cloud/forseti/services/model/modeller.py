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


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc
# pylint: disable=invalid-name


class Modeller(object):
    """Implements the Modeller API."""

    def __init__(self, config):
        self.config = config

    def CreateModel(self, source, name, inventory_id, background):
        """Creates a model from the import source."""

        model_manager = self.config.model_manager
        model_handle = model_manager.create(name=name)
        scoped_session, data_access = model_manager.get(model_handle)

        def doImport():
            """Import runnable."""
            with scoped_session as session:
                importer_cls = importer.by_source(source)
                import_runner = importer_cls(
                    session,
                    model_manager.model(model_handle, expunge=False),
                    data_access,
                    self.config,
                    inventory_id)
                import_runner.run()

        if background:
            self.config.run_in_background(doImport)
        else:
            doImport()
        return model_manager.model(model_handle, expunge=True)

    def ListModel(self):
        """Lists all models."""

        model_manager = self.config.model_manager
        return model_manager.models()

    def DeleteModel(self, model_name):
        """Deletes a model."""

        model_manager = self.config.model_manager
        model_manager.delete(model_name)
