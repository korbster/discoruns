from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class ImageHijacks(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}
        attributes = ['Debugger', 'MonitorProcess', 'AutoRun', '(Default)']

        for artifact in fsw.get_artifacts("WindowsImageHijacks"):
            for value in artifact.get("values", []):
                if value.get("data") and value.get("name") in attributes and not value.get("data") == "\"%1\" %*":
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "image_hijacks", "origins": list(origins), "entry": dll}
                for dll, origins in tmp_dict.items()]
