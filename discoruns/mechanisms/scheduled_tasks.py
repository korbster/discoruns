from xml.dom import minidom

from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


class ScheduledTasks(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        mechanisms = []
        for artifact in fsw.get_files("WindowsScheduledTasks"):
            if "export_path" in artifact and artifact["export_path"] and not artifact["export_path"].endswith(".DAT"):
                # pylint: disable=protected-access
                with fsw._fs_store.load_file(artifact["export_path"]) as io:
                    xml_file = minidom.parse(io)
                    elem = ""
                    arg = ""

                    # Check xml doc for "Command" and "Arguments" tags. Exception wil be ignored if no argument exists.
                    try:
                        elem = xml_file.getElementsByTagName('Command')[0].childNodes[0].data
                        arg = xml_file.getElementsByTagName('Arguments')[0].childNodes[0].data
                    except IndexError:
                        pass

                    if elem:
                        mechanisms.append({
                            "name": "scheduled_tasks",
                            "origins": [artifact.get("origin").get("path")],
                            "entry": " ".join([elem, arg])}
                        )

        return mechanisms
