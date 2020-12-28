from discoruns.mechanism import Mechanism


class PowershellProfiles(Mechanism):

    def collect_mechanism(self, fsw):
        tmp_dict = {}

        for entry in fsw.get_files("WindowsPowerShellDefaultProfiles"):
            tmp_dict.setdefault(entry.get("origin").get("path"), []).extend(entry.get("name"))

        return [{"name": "powershell_profiles", "origins": [path],
                 "entry": entry.pop()} for path, entry in tmp_dict.items()]
