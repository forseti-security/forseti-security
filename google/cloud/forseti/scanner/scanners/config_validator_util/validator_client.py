# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Config Validator Validator Client."""


from builtins import object
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

    DEFAULT_ENDPOINT = 'localhost:50052'

    def __init__(self, endpoint=DEFAULT_ENDPOINT):
        """Initialize

        Args:
            endpoint (String): The Config Validator endpoint.
        """
        self.buffer_sender = BufferedCVDataSender(self)
        self.channel = grpc.insecure_channel(endpoint)
        self.stub = validator_pb2_grpc.ValidatorStub(self.channel)

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception_cv,
           wait_exponential_multiplier=10, wait_exponential_max=100,
           stop_max_attempt_number=5)
    def add_data(self, assets):
        """Add asset data.

        Args:
            assets (list): A list of asset data.

        Raises:
            ConfigValidatorAddDataError: Config Validator Add Data Error.
            ConfigValidatorServerUnavailableError: Config Validator
                Server Unavailable Error.
        """
        try:
            request = validator_pb2.AddDataRequest()
            request.assets.extend(assets)  # pylint: disable=no-member
            self.stub.AddData(request)
        except grpc.RpcError as e:
            # pylint: disable=no-member
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise errors.ConfigValidatorServerUnavailableError(
                    e.message)
            else:
                LOGGER.exception('Failed to add data: %s', assets[0])
                # LOGGER.exception('ConfigValidatorAddDataError: %s', e.message)
                # raise errors.ConfigValidatorAddDataError(e.message)
                return

    def add_data_in_bulk(self, assets):
        """Add asset data to buffer, intended to manage sending data in bulk.

        Args:
            assets (list): A list of asset data.
        """
        for asset in assets:
            self.buffer_sender.add(asset)
        self.buffer_sender.flush()

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception_cv,
           wait_exponential_multiplier=10, wait_exponential_max=100,
           stop_max_attempt_number=5)
    def audit(self):
        """Audit existing data in Config Validator.

        Returns:
            list: List of violations.

        Raises:
            ConfigValidatorAuditError: Config Validator Audit Error.
            ConfigValidatorServerUnavailableError: Config Validator Server
                Unavailable Error.
        """
        try:
            return self.stub.Audit(validator_pb2.AuditRequest()).violations
        except grpc.RpcError as e:
            # pylint: disable=no-member
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise errors.ConfigValidatorServerUnavailableError(
                    e.message)
            else:
                LOGGER.exception('ConfigValidatorAuditError: %s', e.message)
                raise errors.ConfigValidatorAuditError(e.message)

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception_cv,
           wait_exponential_multiplier=10, wait_exponential_max=100,
           stop_max_attempt_number=5)
    def reset(self):
        """Clears previously added data from Config Validator.

        Raises:
            ConfigValidatorResetError: Config Validator Reset Error.
            ConfigValidatorServerUnavailableError: Config Validator Server
                Unavailable Error."""
        try:
            self.stub.Reset(validator_pb2.ResetRequest())
        except grpc.RpcError as e:
            # pylint: disable=no-member
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise errors.ConfigValidatorServerUnavailableError(
                    e.message)
            else:
                LOGGER.exception('ConfigValidatorResetError: %s', e.message)
                raise errors.ConfigValidatorResetError(e.message)


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
