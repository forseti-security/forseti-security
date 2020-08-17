# Copyright 2020 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Config Validator Client."""


from builtins import object
import os
import sys

import grpc
from retrying import retry

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import retryable_exceptions
from google.cloud.forseti.scanner.scanners.config_validator_util import errors
from google.cloud.forseti.scanner.scanners.config_validator_util import (
    validator_pb2)
from google.cloud.forseti.scanner.scanners.config_validator_util import (
    validator_pb2_grpc)

LOGGER = logger.get_logger(__name__)


class ValidatorClient(object):
    """Validator client."""

    DEFAULT_ENDPOINT = os.getenv('CONFIG_VALIDATOR_ENDPOINT',
                                 'localhost:50052')

    def __init__(self, endpoint=DEFAULT_ENDPOINT):
        """Initialize

        Args:
            endpoint (String): The Config Validator endpoint.
        """
        self.buffer_sender = BufferedCVDataSender(self)
        self.max_length = 1024 ** 3
        # Default grpc message size limit is 4MB, set the
        # Audit once every 100 MB of data sent to Config Validator.
        self.max_audit_size = 1024 ** 2 * 100
        self.channel = grpc.insecure_channel(endpoint, options=[
            ('grpc.max_receive_message_length', self.max_length)])
        self.stub = validator_pb2_grpc.ValidatorStub(self.channel)

    # paged_review: Called by CV scanner to scan a generator of resources
    def paged_review(self, assets):
        """Review in a paged manner to avoid memory problem.

        Args:
            assets (Generator): A list of asset data.

        Yields:
            list: A list of violations of the paged assets.
        """
        paged_assets = []
        current_page_size = 0
        for asset in assets:
            asset_size = sys.getsizeof(asset)
            # Dictionary size is not properly reflected, cast the dictionary to
            # string instead to estimate the actual dictionary size.
            asset_size += sys.getsizeof(str(asset.resource))
            asset_size += sys.getsizeof(str(asset.iam_policy))
            if current_page_size + asset_size >= self.max_audit_size:
                violations = self.review(paged_assets)
                if violations:
                    yield violations
                paged_assets = []
                current_page_size = 0
            paged_assets.append(asset)
            current_page_size += asset_size

        if paged_assets:
            violations = self.review(paged_assets)
            if violations:
                yield violations

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception_cv,
           wait_exponential_multiplier=10, wait_exponential_max=100,
           stop_max_attempt_number=5)
    def review(self, assets):
        """Review existing data in Config Validator (Audit in parallel
        per policy).

        Args:
            assets (list): A list of assets to review.

        Returns:
            list: List of violations.

        Raises:
            ConfigValidatorAuditError: Config Validator Audit Error.
            ConfigValidatorServerUnavailableError: Config Validator Server
                Unavailable Error.
        """
        try:

            review_request = validator_pb2.ReviewRequest()
            # pylint: disable=no-member
            review_request.assets.extend(assets)
            # pylint: enable=no-member
            LOGGER.info(f'Config Validator - reviewing {len(assets)} assets')
            return self.stub.Review(review_request).violations
        except grpc.RpcError as e:
            # pylint: disable=no-member
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise errors.ConfigValidatorServerUnavailableError(e)
            else:
                LOGGER.exception('ConfigValidatorAuditError: %s', e)
                raise errors.ConfigValidatorAuditError(e)


class BufferedCVDataSender(object):
    """Buffered Config Validator data sender."""

    MAX_ALLOWED_PACKET = 4000000  # Default grpc message size limit is 4MB.

    def __init__(self,
                 validator_client,
                 max_size=1024,
                 max_packet_size=MAX_ALLOWED_PACKET):
        """Initialize.

        Args:
            validator_client (ValidatorClient): The validator client.
            max_size (int): max size of buffer.
            max_packet_size (int): max size of a packet to send to Config
                Validator.
        """
        self.validator_client = validator_client
        self.buffer = []
        self.packet_size = 0
        self.max_size = max_size
        self.max_packet_size = max_packet_size

    def add(self, asset):
        """Add an Asset to the buffer to send to Config Validator.

        Args:
            asset (Asset): Asset to send to Config Validator.
        """

        self.buffer.append(asset)
        asset_size = sys.getsizeof(asset)
        if self.packet_size + asset_size > self.max_packet_size:
            self.flush()
        self.packet_size += asset_size
        self.packet_size += sys.getsizeof(asset)
        if len(self.buffer) >= self.max_size:
            self.flush()

    def flush(self):
        """Flush all pending objects to the database."""
        self.validator_client.add_data(self.buffer)
        self.buffer = []
        self.packet_size = 0
