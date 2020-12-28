from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class SIPAndTrustProviderHijacking(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsSIPandTrustProviderHijacking"):
            for value in artifact.get("values", []):
                name = value.get("name", "").casefold()
                if name == "Dll".casefold() or name == "'$DLL'".casefold() and value.get("data"):
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "sip_and_trust_provider_hijacking", "origins": list(origins), "entry": dll}
                for dll, origins in tmp_dict.items()]
