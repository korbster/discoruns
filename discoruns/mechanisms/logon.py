import configparser
import os

from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


def process_ini_values(tmp_dict: dict, file_path: str, section: str, file_origin: str):
    config = configparser.ConfigParser()
    config.read(file_path, encoding="UTF-16")

    logon_entries = zip(list(config[section])[::2], list(config[section])[1::2])
    for cmd_key, arg_key in logon_entries:
        tmp_dict.setdefault(config[section][cmd_key] + " " + config[section][arg_key], set()).add(file_origin)


def get_file_origin(fsw, file_path):
    return [file.get("origin").get("path") for file in fsw.get_files("WindowsGroupPolicyScripts")
            if file.get("export_path") in file_path]


class Logon(Mechanism):

    def collect_mechanism(self, fsw: ForensicStoreWrapper) -> list:
        mechanisms = []
        tmp_dict = {}

        # Windows Environment Logon Scripts
        for artifact in fsw.get_artifacts("WindowsEnvironmentUserLoginScripts"):
            for value in artifact.get("values", []):
                if value.get("data"):
                    tmp_dict.setdefault(value.get("data"), set()).add(artifact.get("key"))

        for dll, origins in tmp_dict.items():
            mechanisms.append({"name": "user_environment_script", "origins": list(origins), "entry": dll})

        # Windows Group Policy Scripts
        folder_path = os.path.join(fsw.forensicstore_path, "WindowsGroupPolicyScripts/")
        if os.path.exists(folder_path):
            for file in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file)
                file_origin = get_file_origin(fsw, file_path)[0]

                # Group Policy Logon and Logoff Scripts
                if file.endswith("GroupPolicy_User_Scripts_scripts.ini"):
                    process_ini_values(tmp_dict, file_path, "Logon", file_origin)
                    process_ini_values(tmp_dict, file_path, "Logoff", file_origin)

                # Group Policy Startup and Shutdown Scripts
                elif file.endswith("GroupPolicy_Machine_Scripts_scripts.ini"):
                    process_ini_values(tmp_dict, file_path, "Startup", file_origin)
                    process_ini_values(tmp_dict, file_path, "Shutdown", file_origin)

                # Filesystem Startup and Shutdown Scripts
                elif file.endswith(".exe"):
                    if "Shutdown" in file:
                        mechanisms.append({"name": "logon", "origins": [file_origin],
                                           "entry": file.partition("Shutdown_")[2]})
                    elif "Startup" in file:
                        mechanisms.append({"name": "logon", "origins": [file_origin],
                                           "entry": file.partition("Startup_")[2]})
                    elif "Logon" in file:
                        mechanisms.append({"name": "logon", "origins": [file_origin],
                                           "entry": file.partition("Logon_")[2]})
                    elif "Logoff" in file:
                        mechanisms.append({"name": "logon", "origins": [file_origin],
                                           "entry": file.partition("Logoff_")[2]})

        # Windows Startup Scripts
        tmp_vals = {}
        for artifact in fsw.get_artifacts("WindowsStartupScript"):
            for value in artifact.get("values", []):
                if value.get("name") == "Parameters":
                    tmp_vals.setdefault(artifact.get("key"), {}).update({"param": value.get("data")})
                elif value.get("name") == "Script":
                    tmp_vals.setdefault(artifact.get("key"), {}).update({"script": value.get("data")})
                else:
                    tmp_vals.setdefault(artifact.get("key"), {}).update({"script": value.get("data"), "param": None})

        for key, entries in tmp_vals.items():
            tmp_dict.setdefault(" ".join(filter(None, [entries.get("script"), entries.get("param")])), set()).add(key)

        # Windows Startup Folders
        for file in fsw.get_files("WindowsStartupFolders"):
            if file.get("name", "").endswith(".exe", None):
                mechanisms.append(
                    {"name": "logon", "origins": [file.get("origin").get("path")], "entry": file.get("name")})

        return [{"name": "logon", "origins": list(origins), "entry": entry}
                for entry, origins in tmp_dict.items()]
