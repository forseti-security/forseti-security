from google.cloud.forseti.scanner.scanners.gcv_util import validator_pb2
from google.cloud.forseti.scanner.scanners.gcv_util import validator_pb2_grpc


class ValidatorClient(object):
    """Validator client."""

    DEFAULT_CHANNEL = 'localhost:50052'

    def __init__(self, channel=DEFAULT_CHANNEL):
        """Initialize

        Args:
            channel (String): The default Validator channel.
        """
        self.buffer_sender = BufferedGCVDataSender(self)
        self.stub = validator_pb2_grpc.ValidatorStub(channel)

    def add_data(self, assets):
        """Add asset data.

        assets (list): A list of asset data.
        """
        request = validator_pb2.AddDataRequest(assets=assets)
        self.stub.AddData(request)

    def audit(self):
        """Audit existing data in GCV.

        Returns:
            list: List of violations.
        """
        self.stub.Audit()

    def reset(self):
        """Clears previously added data from GCV."""
        self.stub.Reset()


class BufferedGCVDataSender(object):
    """Buffered GCV data sender."""

    MAX_ALLOWED_PACKET = 4000000  # Default grpc message size limit is 4MB.

    def __init__(self,
                 validator_client,
                 max_size=1024,
                 max_packet_size=MAX_ALLOWED_PACKET * .75):
        """Initialize.

        Args:
            validator_client (ValidatorClient): The validator client.
            max_size (int): max size of buffer.
            max_packet_size (int): max size of a packet to send to GCV.
        """
        self.validator_client = validator_client
        self.buffer = []
        self.estimated_packet_size = 0
        self.max_size = max_size
        self.max_packet_size = max_packet_size

    def add(self, asset, estimated_length=0):
        """Add an object to the buffer to write to db.

        Args:
            asset (Asset): Asset to send to GCV.
            estimated_length (int): The estimated length of this object.
        """

        self.buffer.append(asset)
        self.estimated_packet_size += estimated_length
        if (self.estimated_packet_size > self.max_packet_size or
                len(self.buffer) >= self.max_size):
            self.flush()

    def flush(self):
        """Flush all pending objects to the database."""
        self.validator_client.add_data(self.buffer)
        self.buffer = []
        self.estimated_packet_size = 0
