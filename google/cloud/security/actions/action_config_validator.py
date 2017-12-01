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

"""Actions configuration validator."""

from collections import defaultdict
import importlib
import os
import yaml

class ActionsConfigValidator(object):
    """ActionsConfigValidator class.

    Contains basic validation that should be done on all action configurations.
    """

    @staticmethod
    def validate(actions_config_path):
        """Validates the actions config.

        Action configuration validation:
        1. Config is a valid yaml file.
        2. Each action has an id and it is unique.
        3. Check each action for:
          1. An action type.
          2. That the action type is valid.
          3. A trigger.
          4. That the trigger is valid.

        Args:
            actions_config_path (str): The actions configuration path.

        Returns:
            tuple: A tuple with the dict configuration and the list of errors.

        Raises:
            ConfigLoadError: If the config cannot be loaded.
        """
        errors = []
        config = ActionsConfigValidator._load_and_validate_yaml(
            actions_config_path)

        actions, errs = ActionsConfigValidator._load_actions(config)
        errors.extend(errs)

        for action in actions:
            action_errs = []
            action_errs.append(
                ActionsConfigValidator._check_action_type(action))
            action_errs.append(ActionsConfigValidator._check_trigger(action))
            for err in action_errs:
                if err is not None:
                    errors.append(err)
        return config, errors

    @staticmethod
    def _load_and_validate_yaml(path):
        """Loads the configuration from a path.

        Args:
          path (str): The path the the configuration.

        Returns:
          dict: The loaded configuration dictionary.

        Raises:
          ConfigLoadError: If the config cannot be loaded.
        """
        with open(os.path.abspath(path), 'rb') as filep:
            try:
                config = yaml.safe_load(filep)
            except ValueError as yaml_error:
                raise ConfigLoadError(yaml_error)
        return config

    @staticmethod
    def _load_actions(config):
        """Loads the actions actions from the config.

        Args:
          config (dict): A dictionary configuration.

        Returns:
          Tuple: A tuple of the actions and errors.
        """
        action_ids = defaultdict(int)
        actions = []
        errors = []
        for action in config.get('actions', []):
            action_id = action.get('id')
            if action_id is None:
                errors.append(MissingRequiredActionField('id'))
            action_ids[action_id] += 1
            if action_ids[action_id] > 1:
                errors.append(DuplicateActionIdError(action_id))
            actions.append(action)
        return actions, errors

    @staticmethod
    def _check_action_type(action):
        """Validates the action type.

        Args:
          action (dict): An action dictionary.

        Returns:
          ActionTypeDoesntExist: If the action type doesn't exist.
        """
        action_id = action.get('id')
        action_type = action.get('type')
        if not action_type:
            return EmptyActionType(action_id)
        parts = action_type.split('.')
        try:
            module = importlib.import_module('.'.join(parts[:-1]))
            _ = getattr(module, parts[-1])
        except (AttributeError, ImportError):
            return ActionTypeDoesntExist(action_type)
        return None

    @staticmethod
    def _check_trigger(action):
        """Validates the triggers.

        Args:
          action (dict): An action dictionary.

        Returns:
          Error: If the trigger type doesn't exist or the trigger is missing.
        """
        action_id = action.get('id')
        action_triggers = action.get('triggers')
        if not action_triggers:
            return EmptyActionTrigger(action_id)
        for trigger in action_triggers:
            parts = trigger.split('.')
            if not parts[0] == 'rules':
                return TriggerDoesntExist(trigger)
            # TODO: once the rules classes and the action classes are set up,
            # this should be changed handle any valid type instead of straight
            # replacement.
            parts[0] = 'google.cloud.security.auditor.rules'
            try:
                module = importlib.import_module('.'.join(parts[:-1]))
                _ = getattr(module, parts[-1])
            except (AttributeError, ImportError):
                return TriggerDoesntExist(trigger)
        return None


class Error(Exception):
    """Base Error class."""


class ConfigLoadError(Error):
    """ConfigLoadError."""


class MissingRequiredActionField(Error):
    """MissingRequiredActionField."""


class EmptyActionType(Error):
    """EmptyActionType."""


class EmptyActionTrigger(Error):
    """EmptyActionType."""


class ActionTypeDoesntExist(Error):
    """ActionTypeDoesntExist."""


class TriggerDoesntExist(Error):
    """ActionTypeDoesntExist."""


class DuplicateActionIdError(Error):
    """DuplicateActionIdError."""

    CUSTOM_ERROR_MSG = 'Found duplicate action id: {0}'

    def __init__(self, action_id):
        """Initialize DuplicateActionIdError.
        Args:
          action_id (str): The string action id.
        """
        super(DuplicateActionIdError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(action_id))
        self.action_id = action_id
