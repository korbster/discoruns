import logging
import sqlite3

import forensicstore

logger = logging.getLogger(__name__)


class ForensicStoreWrapper:
    """
    This is a wrapper class for the forensicstore database.
    """

    def __init__(self, forensicstore_path: str):
        """
        Initializes forensicstore wrapper class.

        :param forensicstore_path: Path to an existing forensicstore.
        """

        self.forensicstore_path = forensicstore_path
        self._fs_store = forensicstore.open(self.forensicstore_path)

    def get_artifacts(self, artifact_name: str):
        try:
            registry_values = self._fs_store.select([{"type": "windows-registry-key", "artifact": artifact_name}])

            logger.debug("Collecting '%s' persistence mechanism.", artifact_name)
            return list(registry_values)

        except sqlite3.OperationalError:
            return []

        except Exception as exception:
            logger.exception(exception)

    def get_files(self, artifact_name: str):
        try:
            registry_values = self._fs_store.select([{"type": "file", "artifact": artifact_name}])
            logger.debug("Collecting '%s' file information.", artifact_name)
            return list(registry_values)

        except sqlite3.OperationalError:
            return []

        except Exception as exception:
            logger.exception(exception)

    def close(self):
        self._fs_store.close()
