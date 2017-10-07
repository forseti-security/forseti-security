class RulesEngine(object):
    """Parse and validate rule configuration schema."""

    def __init__(self, rules_config_path):
        self.valid_rules = []
        self.rules_config_path = rules_config_path

    def setup(self):
        self.validate_config()
        self.rules = self.parse_config()

    def parse_config(self):
        return []

    def validate_config(self):
        pass

    def _check_unique_rule_ids(self):
        return True

    def evaluate_rules(self, resource):
        for rule in self.valid_rules:
            result = rule.audit(resource)
        return []


class RuleResult(object):
    """The result of rule evaluation."""
