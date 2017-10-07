import importlib

from google.cloud.security.auditor import condition_parser


class Rule(object):
    """The base class for Rules."""

    def __init__(self, rule_id=None, description=None):
        self.rule_id = rule_id
        self.description = description
        self.condition_params = []
        self.resource_config = []
        self.condition = None

    @staticmethod
    def create_rule(rule_definition):
        """Instantiate a rule based on its definition.

        Args:
            rule_definition (dict): The rule definition properties.

        Return:
            object: An instance of Rule.
        """
        parts = rule_definition.get('type').split('.')
        module = importlib.import_module('.'.join(parts[:-1]))
        rule_class = getattr(module, parts[-1])
        new_rule = rule_class()

        # Set properties
        new_rule.rule_id = rule_definition.get('id')
        new_rule.description = rule_definition.get('description')
        
        config = rule_definition.get('configuration', {})
        new_rule.condition_params = config.get('variables')
        new_rule.resource_config = config.get('resources')
        new_rule.condition_stmt = config.get('condition')
        return new_rule

    def audit(self, resource):
        """Audit the rule definition + resource."""
        return True

    @property
    def type(self):
        return '%s.%s' % (self.__module__, self.__class__.__name__)

