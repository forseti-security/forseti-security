from google.cloud.forseti.scanner.scanners.gcv_util import validator_pb2


SUPPORTED_DATA_TYPE = ['iam_policy', 'resource']


def convert_resource_type_to_cai_format(resource_type):
    """Convert the GCP type to cai format.

    You can read more about the supported types in:
        google.cloud.forseti.model.importer.GCP_TYPE_LIST

    Args:
        resource_type (string): GCP resource type.

    Returns:
        str: Resource type in CAI format.
    """
    def _is_compute_resource(resource_type):
        return 'compute_' in resource_type
    def _is_appeng_resource(resource_type):
        return 'appeng_' in resource_type
    def is_crm_resource(resource_type):
        return resource_type in ['organization', 'folder', 'project']
    def is_gcs_resource(resource_type):
        return resource_type in ['bucket']
    def is_csql_resource(resource_type):
        return False
    def is_spanner_resource(resource_type):
        return 'spanner_' in resource_type
    def is_pubsub_resource(resource_type):
        return 'pubsub_' in resource_type
    def is_bigtable_resource(resource_type):
        return 'bigtable_' in resource_type
    def is_redis_resource(resource_type):
        return 'redis_' in resource_type


def convert_data_to_gcv_asset(data, data_type):
    """Convert data to CAI format.

    Args:
        data (dict): Data in dictionary format, can be resource
            data or IAM policy data.
        data_type (str): Type of the data, can either be 'resource'
            or 'iam_policy'.

    Returns:
        Asset: A GCV Asset.

    Raises:
        ValueError: if data_type is have an unexpected type.
    """


    # validator_pb2.Asset

    pass
