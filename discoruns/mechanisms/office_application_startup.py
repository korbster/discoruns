from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class OfficeApplicationStartup(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsOfficeApplicationStartup"):
            for value in artifact.get("values", []):
                if value.get("name") in ["FriendlyName", "URL", "(Default)"]:
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "office_application_startup", "origins": list(origins), "entry": com_object}
                for com_object, origins in tmp_dict.items()]
