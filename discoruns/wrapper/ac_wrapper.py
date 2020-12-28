import logging
import os
import os.path
import subprocess
import sys

logger = logging.getLogger(__name__)


class ArtifactCollectorWrapper:
    """
    This is a wrapper class for the artifact collect command-line tool
    """

    def __init__(self, image_path: str, store_path: str, artifacts_dir: str, artifact_names: str):
        """
        Initializes class with arguments from the command-line

        :param image_path: Path to the input disk image
        :param store_path: Path to the forensicstore output
        :param artifacts_dir: Path to the directory of the artifact definition yamls
        :param artifact_names: List of to-be collected artifacts
        """

        # File and directory paths. Should be also accessible from outside,
        # for example when trying to get output results
        self.image_path = image_path
        self.store_path = store_path
        self.artifacts_dir = artifacts_dir
        self.artifact_names = artifact_names

        # Docker mount points and image name. Could be placed in config file
        self._docker_image_mount = "/elementary/input-dir"
        self._docker_store_mount = "/elementary/input.forensicstore"
        self._docker_artifacts_mount = "/elementary/artifacts-dir"
        self.docker_image_name = "forensicanalysis/elementary-import-image:v0.3.5"

    def collect_artifacts(self):
        """
        Wrapper function for docker run.

        Calls the docker run with custom parameters as subprocess.
        """
        docker_input_mapping = f"{os.path.abspath(os.path.dirname(self.image_path))}:{self._docker_image_mount}"
        docker_output_mapping = f"{os.path.abspath(self.store_path)}:{self._docker_store_mount}"
        docker_artifacts_mapping = f"{os.path.abspath(self.artifacts_dir)}:{self._docker_artifacts_mount}"

        # Docker run subprocess call. "--user" tag makes sure that the output file has same permissions as the host,
        # to be able to access it afterwards.
        subprocess_commands = ["docker", "run", "--rm",
                               "-v", docker_input_mapping,
                               "-v", docker_artifacts_mapping,
                               "-v", docker_output_mapping,
                               f"{self.docker_image_name}",
                               "--input-file", f"{os.path.basename(self.image_path)}",
                               "--artifacts-dir", self._docker_artifacts_mount,
                               "--dir", self._docker_store_mount,
                               "--artifact", f"{self.artifact_names}",
                               "-vvv", f"--input-dir {self._docker_image_mount}"]

        logger.debug("Trying to execute docker run subprocess call to collect artifacts ...")
        logger.debug(" ".join(subprocess_commands))

        try:
            # pylint: disable=subprocess-run-check
            res = subprocess.run(subprocess_commands, capture_output=True)

            logger.debug("Subprocess call returncode: %s", res.returncode)

            # Subprocess return code handling
            if res.returncode == 0:
                if res.stdout:
                    logger.debug(res.stdout.decode("UTF-8"))
                if res.stderr:
                    logger.warning(res.stderr.decode("UTF-8"))
                logger.info("Successfully created forensicstore at: %s", self.store_path)
            else:
                if res.stdout:
                    logger.error(res.stdout.decode("UTF-8"))
                if res.stderr:
                    logger.error(res.stderr.decode("UTF-8"))
                sys.exit(1)

        except FileNotFoundError:
            logger.error("Could not run subprocess call. Maybe docker is not installed?")
