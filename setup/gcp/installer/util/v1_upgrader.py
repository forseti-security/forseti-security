import os
import tempfile

import constants
import files
import utils


class Rule():
    """Rule file."""
    data = {}

    def __init__(self, name, path):
        self.name = name
        self.path = path


class ForsetiV1Configuration():
    """Forseti V1 Configuration."""
    _rules = []
    _config = {}

    def __init__(self, project_id, name, zone):
        """Init.

        Args:
            project_id (str): Id of the project.
            name (str): Name of the v1 vm instance.
            zone (str): Zone of the v1 vm instance.
        """
        self.project_id = project_id
        self.name = name
        self.zone = zone
        timestamp = utils.extract_timestamp_from_name(name)
        self.gcs_location = constants.DEFAULT_BUCKET_FMT_V1.format(
            project_id, timestamp)
        self.populate_rule_paths()

    def populate_rule_paths(self):
        """Populate all the v1 conf/rule paths."""
        for rule_file in constants.FORSETI_V1_RULE_FILES:
            rule_path = '{}/rules/{}'.format(self.gcs_location, rule_file)
            self._rules.append(Rule(rule_file, rule_path))

    def fetch_information_from_gcs(self):
        """Fetch all v1 conf/rules information from GCS."""
        self._fetch_config_from_gcs()
        self._fetch_rules_from_gcs()

    def _fetch_config_from_gcs(self):
        """Fetch v1 configuration from GCS."""
        # Create a temp directory
        tempdir = tempfile.mkdtemp()

        # Copy file from GCS to the temp directory
        config_path = '{}/configs/forseti_conf.yaml'.format(
            self.gcs_location)
        files.copy_file_to_destination(config_path, tempdir)

        # Load the file into dictionary
        local_file_path = os.path.join(tempdir, 'forseti_conf.yaml')
        self._config = files.read_yaml_file_from_local(local_file_path)

        # Remove the saved file and the temp directory
        os.unlink(local_file_path)
        os.rmdir(tempdir)

    def _fetch_rules_from_gcs(self):
        """Fetch v1 rules from GCS."""
        # Create a temp directory
        tempdir = tempfile.mkdtemp()

        rules_to_remove = []

        # Copy files from GCS to the temp directory
        for rule in self._rules:
            success = files.copy_file_to_destination(rule.path, tempdir)
            if not success:
                rules_to_remove.append(rule)
                continue
            local_file_path = os.path.join(tempdir, rule.name)
            self._rules.append(
                files.read_yaml_file_from_local(local_file_path))
            os.unlink(local_file_path)

        # Remove bad rules
        for rule in rules_to_remove:
            self._rules.remove(rule)

        # Remove the saved file and the temp directory
        os.rmdir(tempdir)

    @property
    def rules(self):
        """Rule objects.

        Returns:
            list: List of rule objects
        """
        return self._rules

    @property
    def config(self):
        """Config object.

        Returns:
            dict: Config object
        """
        return self._config
