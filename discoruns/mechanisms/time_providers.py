from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class TimeProviders(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsTimeProviders"):
            for value in artifact.get("values", []):
                if value.get("data") and value.get("name").casefold() == 'DllName'.casefold():
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "time_providers", "origins": list(origins), "entry": dll}
                for dll, origins in tmp_dict.items()]
