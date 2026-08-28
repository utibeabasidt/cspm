from scanner.finding import Finding


class RuleEngine:

    def __init__(self):
        self.rules = []

    def register(self, rule):
        self.rules.append(rule)

    def evaluate(self, bucket_name, config):
        findings = []

        for rule in self.rules:
            finding = rule.evaluate(
                bucket_name,
                config,
            )

            if isinstance(finding, Finding):
                findings.append(finding)

        return findings