from discoruns.mechanism import Mechanism


class AppCertDLLs(Mechanism):

    def collect_mechanism(self, fsw):
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsAppCertDLLsAlt"):
            for value in artifact.get("values", []):
                if value.get("name", "").casefold() == 'AppCertDlls'.casefold() and value.get("data"):
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "app_cert_dlls", "origins": list(origins), "entry": dll} for dll, origins in tmp_dict.items()]
