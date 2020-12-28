from discoruns.mechanism import Mechanism


class AppInitDLLs(Mechanism):

    def collect_mechanism(self, fsw):
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsAppInitDLLs"):
            for value in artifact.get("values", []):
                if value.get("name", "").casefold() == 'AppInit_DLLs'.casefold() and value.get("data"):
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "app_init_dlls", "origins": list(origins), "entry": dll} for dll, origins in tmp_dict.items()]
