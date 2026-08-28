from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    resource: str
    resource_type: str
    status: str
    severity: str
    description: str
    recommendation: str