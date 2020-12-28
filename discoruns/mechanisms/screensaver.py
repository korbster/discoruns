from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class ScreenSaver(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsScreenSaverExecutable"):
            for value in artifact.get("values", []):
                if value.get("data") and value.get("name").casefold() == "scrnsave.exe".casefold():
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "screensaver", "origins": list(origins), "entry": dll}
                for dll, origins in tmp_dict.items()]
