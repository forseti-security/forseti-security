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

"""Class loader util."""

import importlib


def load_class(module_class_name):
    """Load a Forseti class, if it exists.

    Args:
        module_class_name (str): The full module name with the class.

    Returns:
        object: The class, if it exists.

    Raises:
        InvalidForsetiClassError: If the module or class does not exist.
    """
    try:
        parts = module_class_name.split('.')
        module = importlib.import_module('.'.join(parts[:-1]))
        the_class = getattr(module, parts[-1])
        return the_class
    except (AttributeError, ImportError) as err:
        raise InvalidForsetiClassError(module_class_name, err)


class Error(Exception):
    """Base Error class."""


class InvalidForsetiClassError(Error):
    """InvalidForsetiClassError."""

    def __init__(self, module_class_name, err):
        """Init.

        Args:
            module_class_name (str): The module name with the class.
            err (Error): The actual error.
        """
        super(InvalidForsetiClassError, self).__init__(
            'Invalid Forseti class: {} ({})'.format(module_class_name, err))
