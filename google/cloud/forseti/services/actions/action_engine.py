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

"""The action and action engine API implementations."""

import importlib

from google.cloud.forseti.actions import action_config_validator
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class Action(object):

    """The base action class."""

    def __init__(self, config, action_id, action_type):
        """Initializes action.

        Args:
          config (dict): A configuration dict.
          action_id (str): A string action id.
          action_type (str): A string action type.
        """
        self.config = config
        self.action_id = action_id
        self.type = action_type

    def __str__(self):
        """String representation.

        Returns:
          str: A string representation of this object.
        """
        return ('Action(\n' '\tconfig=%s\n'
                '\taction_id=%s\n'
                '\ttype=%s\n') % (self.config, self.action_id, self.type)

    @staticmethod
    def from_dict(action_dict):
        """Creates Action from dictionary config.

        Args:
          action_dict (dict): The configuration dict.

        Raises:
          NotImplementedError: When not implemented.
        """
        raise NotImplementedError

    def act(self, rule_results):
        """Acts on rule results.

        Args:
          rule_results (list): A list of RuleResults.

        Raises:
          NotImplementedError: When not implemented.
        """
        raise NotImplementedError


class SampleAction(Action):
    """An example action."""

    def __init__(self, config, action_id, action_type, code=0, info=''):
        """Initializes SampleAction.

        Args:
          config (dict): The config dictionary.
          action_id (str): A string action id.
          action_type (str): A string action type.
          code (int): The code to send as a result.
          info (str): The info to send as a result.
        """
        super(SampleAction, self).__init__(config, action_id, action_type)
        self.code = code
        self.info = info

    @staticmethod
    def from_dict(action_dict):
        """Creates a SampleAction from a dictionary.

        Args:
          action_dict (dict): A action configuration dictionary.

        Returns:
          SampleAction: The configured SampleAction.

        Raises:
          MissingRequiredActionField: If the action_dict is missing a field.
        """
        action_id = action_dict.get('id')
        if not action_id:
            raise MissingRequiredActionField('id')
        action_type = action_dict.get('type')
        if not action_type:
            raise MissingRequiredActionField('type')
        return SampleAction(action_dict, action_id, action_type)

    def act(self, rule_results):
        """Acts on rule results.

        Args:
          rule_results (list): A list of RuleResults.

        Yields:
          dict: A dictionary of rule results.
        """
        for result in rule_results:
            yield {
                'rule_result': result,
                'code': self.code,
                'action_id': self.action_id,
                'info': self.info
            }

    def __eq__(self, other):
        """Tests SampleAction equality.

        Args:
          other (SampleAction): Object to compare to.

        Returns:
          bool: Comparison result.
        """
        LOGGER.debug('Checking %s == %s', self, other)
        return (self.config == other.config and
                self.action_id == other.action_id and
                self.type == other.type)


class ActionEngine(object):
    """Action engine API implementation."""

    def __init__(self, config_path):
        """Initializes the action engine.

        Args:
          config_path (str): A file path to the configuration.
        """
        self.config_path = config_path
        self.config_dict = action_config_validator.validate(config_path)
        self._action_configs = self.config_dict.get('actions', [])
        self._actions = []
        self.action_types = {
            'Action': Action,
            'SampleAction': SampleAction,
        }

    def _create_actions(self):
        """Creates the actions from the configuration."""
        for action in self._action_configs:
            cls = action.get('type')
            if cls not in self.action_types:
                action_cls = get_action_class(cls)
                self.action_types[cls] = action_cls
            else:
                action_cls = self.action_types[cls]
            self._actions.append(action_cls.from_dict(action))

    @property
    def actions(self):
        """The configured actions.

        Returns:
          list: A list of Actions.
        """
        if not self._actions:
            self._create_actions()
        return self._actions

    def list(self):
        """Lists configured actions.

        Returns:
            list: A list of Actions.
        """
        return self.actions

    def process_results(self, rule_results):
        """Processes rule results.

        Args:
          rule_results (list): A list of RuleResults.

        Returns:
          list: A list of ActionResults.
        """
        action_results = dict((result, []) for result in rule_results)
        for action in self.actions:
            results = action.act(rule_results)
            for result in results:
                action_results[result['rule_result']].append(result)
        return action_results


def get_action_class(cls):
    """Imports the action class.

    Args:
      cls (str): A string action class.

    Returns:
      Action: A child class of Action.

    Raises:
      ActionImportError: If the class doesn't exist.
    """
    parts = cls.split('.')
    module_str = '.'.join(parts[:-1])
    try:
        module = importlib.import_module(module_str)
        module = getattr(module, parts[-1])
    except ImportError as e:
        raise ActionImportError(e)
    return module


class Error(Exception):
    """Base error class for this module."""

class ActionImportError(Error):
    """Error raised when an action cannot be imported."""

class MissingRequiredActionField(Error):
    """Error raised when an action configuration is missing a field."""
