import os
from glob import glob

from discoruns.mechanism import Mechanism
from discoruns.wrapper.fs_wrapper import ForensicStoreWrapper


def collect(fstore_full_path: str) -> list:
    fsw = ForensicStoreWrapper(fstore_full_path)
    plugins_to_run = ['app_cert_dlls',
                      'app_init_dlls',
                      'application_shimming',
                      'authentication_packages',
                      'browser_extensions',
                      'codecs',
                      'com_hijacking',
                      'file_associations',
                      'image_hijacks',
                      'known_dlls',
                      'logon',
                      'netsh_helper',
                      'office_application_startup',
                      'port_monitors',
                      'powershell_profiles',
                      'run_keys',
                      'scheduled_tasks',
                      'screensaver',
                      'security_support_provider',
                      'services_and_drivers',
                      'sip_and_trust_provider_hijacking',
                      'time_providers',
                      'winlogon_helper',
                      'winsock_providers',
                      ]

    # Instantiate all "Mechanism" subclasses (plugins) and collect mechanisms
    mechanisms_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mechanisms")
    for file in glob(os.path.join(mechanisms_folder, "*py")):
        name = os.path.splitext(os.path.basename(file))[0]
        if name in plugins_to_run:
            __import__(f"discoruns.mechanisms.{name}")
    collected_mechanisms = []
    for mechanisms in Mechanism.__subclasses__():
        collected_mechanisms.extend(mechanisms().collect_mechanism(fsw))
    fsw.close()
    return collected_mechanisms
