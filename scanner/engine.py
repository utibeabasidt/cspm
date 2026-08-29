from scanner.finding import Finding


class RuleEngine:

    def __init__(self):
        self.rules = []

    def register(self, rule):
        self.rules.append(rule)

    def evaluate(self, resource, config):
        findings = []

        for rule in self.rules:
            finding = rule.evaluate(
                resource,
                config,
            )

            if isinstance(finding, Finding):
                findings.append(finding)

        return findings