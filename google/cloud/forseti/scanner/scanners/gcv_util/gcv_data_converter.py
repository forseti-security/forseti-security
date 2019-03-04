from google.cloud.forseti.scanner.scanners.gcv_util import validator_pb2


_IAM_POLICY = 'iam_policy'
_RESOURCE = 'resource'

SUPPORTED_DATA_TYPE = frozenset([_IAM_POLICY, _RESOURCE])


def convert_resource_type_to_cai_format(data_type):
    """Convert the GCP type to cai format.

    You can read more about the supported types in:
        google.cloud.forseti.model.importer.GCP_TYPE_LIST

    Args:
        data_type (string): GCP data type, either resource or iam_policy.

    Returns:
        str: Resource type in CAI format.
    """
    return data_type

    # def _is_compute_resource(resource_type):
    #     return 'compute_' in resource_type
    # def _is_appeng_resource(resource_type):
    #     return 'appengine_' in resource_type
    # def is_crm_resource(resource_type):
    #     return resource_type in ['organization', 'folder', 'project']
    # def is_gcs_resource(resource_type):
    #     return resource_type in ['bucket']
    # def is_csql_resource(resource_type):
    #     return 'cloudsql' in resource_type
    # def is_spanner_resource(resource_type):
    #     return 'spanner_' in resource_type
    # def is_pubsub_resource(resource_type):
    #     return 'pubsub_' in resource_type
    # def is_bigtable_resource(resource_type):
    #     return 'bigtable_' in resource_type
    # def is_redis_resource(resource_type):
    #     return 'redis_' in resource_type


def convert_data_to_gcv_asset(resource, data_type):
    """Convert data to CAI format.

    Args:
        resource (Resource): Resource from querying the resources table.
        data_type (str): Type of the data, can either be 'resource'
            or 'iam_policy'.

    Returns:
        Asset: A GCV Asset.

    Raises:
        ValueError: if data_type is have an unexpected type.
    """
    if data_type not in SUPPORTED_DATA_TYPE:
        raise ValueError("Data type %s not supported.", data_type)

    cai_type = convert_resource_type_to_cai_format(data_type)

    return validator_pb2.Asset(name=resource.name,
                               asset_type=cai_type,
                               ancestry_path=resource.full_name,
                               resource=resource.data)
