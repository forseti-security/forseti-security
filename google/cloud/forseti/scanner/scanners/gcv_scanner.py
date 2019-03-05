from retrying import retry

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.scanner.scanners.gcv_util import gcv_data_converter
from google.cloud.forseti.scanner.scanners.gcv_util import validator_client
from google.cloud.forseti.services.model.importer import importer


class GCVScanner(base_scanner.BaseScanner):
    """GCV Scanner."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Constructor for the base pipeline.

         Args:
             global_configs (dict): Global configurations.
             scanner_configs (dict): Scanner configurations.
             service_config (ServiceConfig): Service configuration.
             model_name (str): name of the data model
             snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
             rules (str): Fully-qualified path and filename of the rules file.
         """
        super(GCVScanner, self).__init__(
            global_configs, scanner_configs, service_config,
            model_name, snapshot_timestamp, rules)
        self.validator_client = validator_client.ValidatorClient()

        # Maps CAI resource name-> (full_name, resource_data).
        self.resource_lookup_table = {}

    @staticmethod
    def _flatten_violations(violations):
        """Flatten GCV violations into a dict for each violation.

        Args:
            violations (list): The GCV violations to flatten.

        Yields:
            dict: Iterator of GCV violations as a dict per violation.
        """
        # Refer to the mapping table above to flatten the data.
        for violation in violations:
            continue
        pass

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (List[RuleViolation]): A list of GCV violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _retrieve(self):
        """Retrieves the data for scanner.

        Yields:
            Asset: Google Config Validator Asset.

        Raises:
            ValueError: if resources have an unexpected type.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)

        with scoped_session as session:
            # fetching GCP resources.
            for resource_type in importer.GCP_TYPE_LIST:
                for resource in data_access.scanner_iter(session,
                                                         resource_type):
                    self.resource_lookup_table[resource.type_name] = (
                        resource_type.full_name, resource.data)
                    yield gcv_data_converter.convert_data_to_gcv_asset(
                        resource, 'resource')

            # fetching IAM policy.
            for policy in data_access.scanner_iter(session, 'iam_policy'):
                yield gcv_data_converter.convert_data_to_gcv_asset(
                    policy, 'iam_policy')

    def run(self):
        """Runs the GCV Scanner."""
        # Get all the data in GCV Asset format.
        gcv_assets = self._retrieve()

        # Add asset data to GCV.
        for gcv_asset in gcv_assets:
            self.validator_client.add_data_to_buffer(gcv_asset)

        # Find all violations.
        violations = self.validator_client.audit()

        # Clean up GCV.
        self.validator_client.reset()

        # Output to db.
        self._output_results(violations)
