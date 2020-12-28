from discoruns.mechanism import Mechanism


class AuthenticationPackages(Mechanism):

    def collect_mechanism(self, fsw):
        tmp_reg_keys_dict = {}
        found_auth_packages = set()

        for artifact in fsw.get_artifacts("WindowsLSAAuthenticationPackages"):
            raw_artifact_values = [value.get("data") for value in artifact.get("values", [])
                                   if value.get("name") == "Authentication Packages" and value.get("data")]

            # Some value cleaning since it's boxed in something like this "['exec_1', 'exec_2']"
            for raw_artifact_value in raw_artifact_values:
                cleaned_value = raw_artifact_value.strip('[').strip(']').replace("\'", "").split(",")
                cleaned_value = set(elem.strip(" ") for elem in cleaned_value)

                # Avoiding duplicate entries
                diff = cleaned_value.difference(found_auth_packages)
                for elem in diff:
                    tmp_reg_keys_dict.setdefault(elem, []).append(artifact.get("key"))
                found_auth_packages.update(cleaned_value)

        return [{"name": "authentication_packages", "origins": origins, "entry": package}
                for package, origins in tmp_reg_keys_dict.items()]
