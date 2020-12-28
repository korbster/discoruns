from abc import ABC, abstractmethod
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class Mechanism(ABC):

    @abstractmethod
    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        raise NotImplementedError
