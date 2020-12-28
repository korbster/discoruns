from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class Services(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}
        mechanisms = []

        for artifact in fsw.get_artifacts("WindowsServices"):
            for value in artifact.get("values", []):
                name = value.get("name", "").casefold()
                if name == "ServiceDll".casefold() or name == "ImagePath".casefold() and value.get("data"):
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        for artifact in fsw.get_artifacts("WindowsFontDriversAlt"):
            for value in artifact.get("values", []):
                tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        for entry, origins in tmp_dict.items():
            if entry.endswith(".sys"):
                mechanisms.append({"name": "driver", "origins": list(origins), "entry": entry})
            else:
                mechanisms.append({"name": "service", "origins": list(origins), "entry": entry})

        return mechanisms
