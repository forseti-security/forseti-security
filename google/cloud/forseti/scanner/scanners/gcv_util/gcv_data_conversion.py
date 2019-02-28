from google.cloud.forseti.scanner.scanners.gcv_util import validator_pb2


SUPPORTED_DATA_TYPE = ['iam_policy', 'resource']


def convert_data_to_gcv_asset(data, data_type):
    """Convert data to CAI format.

    Args:
        dict: Data in dictionary format, can be resource
            data or IAM policy data.
        str: Type of the data, can either be 'resource'
            or 'iam_policy'.

    Returns:
        Asset: Data in CAI format.

    Raises:
        ValueError: if data_type is have an unexpected type.
    """


    # validator_pb2.Asset

    pass
