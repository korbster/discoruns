from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


def _process_artifacts(tmp_dict, fsw, artifact_name, value_name):
    for artifact in fsw.get_artifacts(artifact_name):
        for value in artifact.get("values", []):
            if value.get("data") and value.get("name").casefold() == value_name.casefold():
                tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))


class WinsockProviders(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}
        artifact_data = [("WinSock2LayeredServiceProviders", "LibraryPath"),
                         ("WinSock2NamespaceProviders", "LibraryPath")]

        for artifact_name, value_name in artifact_data:
            _process_artifacts(tmp_dict, fsw, artifact_name, value_name)

        return [{"name": "winsock_providers", "origins": list(origins), "entry": helper}
                for helper, origins in tmp_dict.items()]
