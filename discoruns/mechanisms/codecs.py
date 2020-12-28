from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class Codecs(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsCodecs"):
            for value in artifact.get("values", []):
                if value.get("name", ""):
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "codecs", "origins": list(origins), "entry": entry}
                for entry, origins in tmp_dict.items()]
