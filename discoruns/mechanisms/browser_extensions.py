import json
import os

from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class BrowserExtensions(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}
        folder_path = os.path.join(fsw.forensicstore_path, "WindowsBrowserPersistenceFiles/")
        if os.path.exists(folder_path):
            for file in os.listdir(folder_path):
                if file.endswith(".json"):
                    file_path = os.path.join(folder_path, file)
                    with open(file_path) as io:
                        for addon in json.load(io).get("addons"):
                            name = addon.get("defaultLocale", {}).get("name")
                            path = addon.get("path", "Unkonwn")
                            if addon.get("active") and name != "Default" and path:
                                tmp_dict.setdefault(name, set()).add(path)

        for artifact in fsw.get_artifacts("WindowsBrowserPersistenceKeys"):
            for value in artifact.get("values", []):
                if value.get("name") in ["(Default)", "ToolTip"]:
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "browser_extensions", "origins": list(origins), "entry": extension_data}
                for extension_data, origins in tmp_dict.items()]
