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

"""Utils for Forseti Server services testing."""

import os
import tempfile

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.dao import create_engine

LOGGER = logger.get_logger(__name__)


def create_test_engine(enforce_fks=True):
    """Create a test engine with a db file in /tmp/."""

    engine, _ = create_test_engine_with_file(enforce_fks=enforce_fks)
    return engine


def create_test_engine_with_file(enforce_fks=True):
    """Create a test engine with a db file in /tmp/."""

    fd, tmpfile = tempfile.mkstemp('.db', 'forseti-test-')
    try:
        LOGGER.info('Creating database at %s', tmpfile)
        engine = create_engine('sqlite:///{}'.format(tmpfile),
                               sqlite_enforce_fks=enforce_fks,
                               connect_args={'check_same_thread': True})
        return engine, tmpfile
    finally:
        os.close(fd)


def cleanup(test_callback):
    """Decorator based model deletion."""

    def wrapper(client):
        """Decorator implementation."""
        for model in client.list_models():
            client.delete_model(model.handle)
        test_callback(client)

    return wrapper
