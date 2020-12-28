from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class FileAssociations(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        tmp_dict = {}

        for artifact in fsw.get_artifacts("WindowsFileAssociation"):
            if values := artifact.get("values"):

                # Find the last program the extension was opened with via MRUList.
                mru_lists = [value.get("data") for value in values if value.get("name") == "MRUList"]
                mru_list = ""
                if len(mru_lists) == 1:
                    mru_list = mru_lists[0]

                last_prog_char = ""
                if len(mru_list) >= 1:
                    last_prog_char = mru_list[0]

                for value in artifact.get("values", []):
                    if value.get("data") and value.get("name") == last_prog_char:
                        tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        return [{"name": "file_associations", "origins": list(origins), "entry": association}
                for association, origins in tmp_dict.items()]
