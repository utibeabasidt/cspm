from abc import ABC, abstractmethod


class SecurityRule(ABC):

    @property
    @abstractmethod
    def rule_id(self):
        pass

    @property
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def evaluate(self, resource, config):
        pass