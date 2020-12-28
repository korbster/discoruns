import os

from discoruns.mechanism import Mechanism


class ApplicationShimming(Mechanism):

    def collect_mechanism(self, fsw):
        tmp_dict = {}
        folder_path = os.path.join(fsw.forensicstore_path, "WindowsApplicationCompatibilityInstalledShimDatabases/")

        if os.path.exists(folder_path):
            for file in os.listdir(folder_path):
                if file.endswith(".sdb"):
                    for entry in fsw.get_files("WindowsApplicationCompatibilityInstalledShimDatabases"):
                        tmp_dict.setdefault(entry.get("name"), set()).add(entry.get("origin").get("path"))

        return [{"name": "application_shimming", "origins": list(path),
                 "entry": entry} for entry, path in tmp_dict.items()]
