from retrying import retry


from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import retryable_exceptions
from google.cloud.forseti.scanner.scanners import base_scanner


class GCVScanner(base_scanner.BaseScanner):

    @staticmethod
    def _flatten_violations(violations):
        """Flatten GCV violations into a dict for each violation.

        Args:
            violations (list): The GCV violations to flatten.

        Yields:
            dict: Iterator of GCV violations as a dict per violation.
        """
        # Refer to the mapping table above to flatten the data.
        pass

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception, wait_exponential_multiplier=1000,
           wait_exponential_max=10000, stop_max_attempt_number=5)
    def _find_violations(self):
        """Find violations by querying the GCV instance.

        Returns:
            list: A list of violations returned by GCV.

        Raises:
            GCVServerUnavailableError: if the GCV server is not available after retries.
            GCVQueryError: if the GCV server is available but unable to query.
        """
        # Invoke GCV Query.
        # Return results returned from GCV Query.

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (List[RuleViolation]): A list of GCV violations.
        """
        pass

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception, wait_exponential_multiplier=1000,
           wait_exponential_max=10000, stop_max_attempt_number=5)
    def _add_data(self, data):
        """Add data to GCV.

        Yields:
            list: A list of data to add to GCV.

        Raises:
            GCVServerUnavailableError: if the GCV server is not available after retries.
            GCVAddDataError: if the GCV server is available but failed to add data.
        """
        pass

    def _retrieve(self):
        """Retrieves the data for scanner.

        Yields:
            rtype: (dict, dict): Resource and IAM policy in CAI format.

        Raises:
            ValueError: if resources have an unexpected type.
        """
        # Get the root resource data & iam policy from model.
        # iam_policy = [root iam policy]
        # for resource, policy in _retrieve_dfs(root, iam_policy):
        #   yield _convert_to_cai(resource, 'resource'), _convert_to_cai(policy,
        #     'iam_policy')
        # yield convert_to_cai(root_resource, 'resource'),
        #   convert_to_cai(root_policy, 'iam_policy')

    @classmethod
    def _retrieve_dfs(root, iam_policy):
        """Retrieves the resource data and iam policy with DFS.

        Yields:
            rtype: (dict, dict): Resource data and IAM policy.
        """
        pass

    @classmethod
    def _convert_to_cai(data, data_type):
        """Convert data to CAI format.

        Args:
            dict: Data in dictionary format, can be resource data or IAM policy data.
            str: Type of the data, can either be 'resource' or 'iam_policy'.

        Returns:
            dict: Data in CAI format.

        Raises:
            ValueError: if data_type is have an unexpected type.
        """
        pass

    def run(self):
        """Runs the GCV Scanner."""
        # 1. Call _retrieve() and get a generator.
        # 2. Generate data in chunks.
        # 3. Call _add_data() with that chunk of data.
        # 4. Repeat steps above until the generator is empty.
        # 5. Call _find_violations.
        # 6. Call _flatten_violations on all the violations returned from 5.
        # 7. Store the violations in the db.
        cai_fmt_data = self._retrieve()

        for data in cai_fmt_data:
            pass
