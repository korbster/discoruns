from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class COMHijacking(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsCOMProperties"):
            for value in artifact.get("values", []):
                if value.get("name") == "(Default)":
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "com_hijacking", "origins": list(origins), "entry": com_object}
                for com_object, origins in tmp_dict.items()]
