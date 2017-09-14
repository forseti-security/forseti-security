import abc


class RulesEngine(object):

    def parse_config(self):
        return []

    def validate_config(self):
        return []

    def evaluate_rules(self, resource):
        return []


class BaseRule(object):

    def create_rule(self, rule_definition):
        pass

    @property
    def id(self):
        pass

    @property
    def description(self):
        pass

    @property
    def type(self):
        pass

    def audit(self, resource):
        return True
