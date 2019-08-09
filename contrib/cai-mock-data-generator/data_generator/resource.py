import random
import string

import data_generator.resource_template as tmpl


class Resource(object):
    def __init__(self,
                 cai_name,
                 cai_type,
                 resource_id,
                 resource_number,
                 resource_type,
                 resource_data,
                 resource_iam_policy='',
                 parent_resource=None):
        """Init.

        Args:
            cai_name (str): CAI resource name.
            cai_type (str): CAI resource type.
            resource_id (str): Resource id.
            resource_number (str): Resource number.
            resource_type (str): Resource type.
            resource_data (str): Resource data.
            resource_iam_policy (str): Resource iam policy.
            parent_resource (Resource): Parent resource.
        """
        self.cai_resource_name = cai_name
        self.cai_resource_type = cai_type
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.resource_data = self.clean_up_format(resource_data)
        self.resource_iam_policy = self.clean_up_format(resource_iam_policy)
        self.resource_number = resource_number
        self.parent_resource = parent_resource

    @staticmethod
    def clean_up_format(dirty_str):
        """Clean up the format of a string.

        Args:
            dirty_str (str): The dirty string.

        Returns:
            str: A clean string.
        """
        return dirty_str.replace('\r', '').replace('\n', '').replace('\\\'', '\'').replace(' ', '')


def _generate_random_id(length=12, number_only=True):
    """Generate random id.

    Args:
        length (int): Length of the id.
        number_only (bool): Generate id consists of number only.

    Returns:
        str: Generated id.
    """
    options = '0123456789'
    if not number_only:
        options += string.ascii_lowercase
    generated_id = ''
    for i in range(0, length):
        generated_id += options[random.randint(0, len(options)-1)]
    return generated_id


def _generate_iam_policy(cai_resource_name, cai_resource_type, roles, max_role_count=5, max_member_count=3):
    """Generate iam policy.

    The resulting iam binding in the policy will always be <= max_role_count
    roles and <=max_member_count members per role.

    Args:
        cai_resource_name (str): CAI resource name.
        cai_resource_type (str): CAI resource type.
        max_role_count (int): The max count of the roles in the binding.
        max_member_count (int): The max count of member assigned to each role.

    Returns:
        string: List of iam policy.
    """
    bindings = []
    role_idx_used = set()
    for i in range(0, max_role_count):
        role_idx = random.randint(0, len(roles)-1)
        if role_idx in role_idx_used:
            continue
        role = roles[role_idx]
        members = []
        for j in range(0, max_member_count):
            member_idx = random.randint(0, len(tmpl.FAKE_IAM_MEMBERS)-1)
            member = tmpl.FAKE_IAM_MEMBERS[member_idx]
            if member not in members:
                members.append(member)

        # Need to clean up the string here as the new line characters will
        # be embedded inside the iam policy.
        bindings.append(tmpl.IAM_BINDING.format(
            ROLE=role,
            MEMBER_LIST=members).replace('\r', '').replace('\n', ''))

    return tmpl.IAM_POLICY.format(CAI_RESOURCE_NAME=cai_resource_name,
                                  CAI_RESOURCE_TYPE=cai_resource_type,
                                  IAM_BINDING=bindings)


def generate_organization(resource_id=''):
    """Generate organization resource.

    Args:
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    display_name = _generate_random_id(number_only=False)
    resource_id = resource_id if resource_id != '' else _generate_random_id()
    resource_type = 'organizations'
    cai_resource_name = '//cloudresourcemanager.googleapis.com/organizations/{}'.format(resource_id)
    cai_resource_type = 'cloudresourcemanager.googleapis.com/Organization'
    resource_data = tmpl.ORGANIZATION.format(ORGANIZATION_NUMBER=resource_id,
                                             DISPLAY_NAME=display_name)
    resource_iam_policy = _generate_iam_policy(cai_resource_name, cai_resource_type, tmpl.ORGANIZATION_ROLES)
    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy=resource_iam_policy)


def generate_folder(parent_resource=None, resource_id=''):
    """Generate folder resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    display_name = _generate_random_id(number_only=False)
    resource_id = resource_id if resource_id != '' else _generate_random_id()
    resource_type = 'folders'
    cai_resource_name = '//cloudresourcemanager.googleapis.com/folders/{}'.format(resource_id)
    cai_resource_type = 'cloudresourcemanager.googleapis.com/Folder'
    resource_data = tmpl.FOLDER.format(FOLDER_NUMBER=resource_id,
                                       PARENT_CAI_NAME=parent_resource.cai_resource_name if parent_resource else '',
                                       DISPLAY_NAME=display_name,
                                       PARENT_TYPE=parent_resource.resource_type if parent_resource else '',
                                       PARENT_ID=parent_resource.resource_id if parent_resource else '')
    resource_iam_policy = _generate_iam_policy(cai_resource_name, cai_resource_type, tmpl.FOLDER_ROLES)
    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy=resource_iam_policy,
                    parent_resource=parent_resource)


def generate_project(parent_resource=None, resource_id=''):
    """Generate project resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    project_id = _generate_random_id(number_only=False)
    resource_id = resource_id if resource_id != '' else _generate_random_id()
    resource_type = 'projects'
    cai_resource_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(resource_id)
    cai_resource_type = 'cloudresourcemanager.googleapis.com/Project'
    resource_data = tmpl.PROJECT.format(PROJECT_NUMBER=resource_id,
                                        PROJECT_ID=project_id,
                                        PARENT_CAI_NAME=parent_resource.cai_resource_name if parent_resource else '',
                                        DISPLAY_NAME=project_id,
                                        PARENT_TYPE=parent_resource.resource_type if parent_resource else '',
                                        PARENT_ID=parent_resource.resource_id if parent_resource else '')
    resource_iam_policy = _generate_iam_policy(cai_resource_name, cai_resource_type, tmpl.PROJECT_ROLES)
    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy=resource_iam_policy,
                    parent_resource=parent_resource)


def generate_bucket(parent_resource, resource_id=''):
    """Generate bucket resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'buckets'
    cai_resource_name = '//storage.googleapis.com/{}'.format(resource_id)
    cai_resource_type = 'storage.googleapis.com/Bucket'
    resource_data = tmpl.BUCKET.format(BUCKET_ID=resource_id,
                                       PARENT_CAI_NAME=parent_resource.cai_resource_name,
                                       PARENT_ID=parent_resource.resource_id)
    resource_iam_policy = _generate_iam_policy(cai_resource_name, cai_resource_type, tmpl.BUCKET_ROLES)
    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy=resource_iam_policy,
                    parent_resource=parent_resource)


def generate_bigquery_dataset(parent_resource, resource_id=''):
    """Generate bigquery dataset resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'bigquery_dataset'
    cai_resource_name = '//bigquery.googleapis.com/projects/{}/datasets/{}'.format(parent_resource.resource_id, resource_id)
    cai_resource_type = 'bigquery.googleapis.com/Dataset'
    resource_location = tmpl.RESOURCE_LOCATIONS[random.randint(0,1)]
    resource_data = tmpl.BIGQUERY_DATASET.format(DATASET_ID=resource_id,
                                                 PARENT_CAI_NAME=parent_resource.cai_resource_name,
                                                 PROJECT_ID=parent_resource.resource_id,
                                                 LOCATION=resource_location)
    resource_iam_policy = _generate_iam_policy(cai_resource_name, cai_resource_type, tmpl.BIGQUERY_ROLES)
    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy=resource_iam_policy,
                    parent_resource=parent_resource)


def generate_bigquery_table(parent_resource, resource_id=''):
    """Generate bigquery table resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'bigquery_table'
    cai_resource_name = '//bigquery.googleapis.com/projects/{}/datasets/{}/tables/{}'.format(
        parent_resource.parent_resource.resource_id,
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'bigquery.googleapis.com/Table'
    resource_data = tmpl.BIGQUERY_TABLE.format(
        TABLE_ID=resource_id,
        DATASET_ID=parent_resource.resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name,
        PROJECT_ID=parent_resource.parent_resource.resource_id)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)


def generate_service_account(parent_resource, resource_id=''):
    """Generate service account resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'service_account'
    cai_resource_name = '//iam.googleapis.com/projects/{}/serviceAccounts/{}'.format(
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'iam.googleapis.com/ServiceAccount'
    resource_data = tmpl.SERVICE_ACCOUNT.format(
        SERVICE_ACCOUNT_ID=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name,
        DISPLAY_NAME=resource_id,
        PROJECT_ID=parent_resource.resource_id)

    resource_iam_policy = _generate_iam_policy(cai_resource_name, cai_resource_type, tmpl.BIGQUERY_ROLES)
    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy=resource_iam_policy,
                    parent_resource=parent_resource)


def generate_appengine_application(parent_resource, resource_id=''):
    """Generate appengine application resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'appengine_application'
    cai_resource_name = '//appengine.googleapis.com/apps/{}'.format(
        resource_id)
    cai_resource_type = 'appengine.googleapis.com/Application'
    resource_data = tmpl.APPENGINE_APPLICATION.format(
        APPENGINE_APPLICATION_ID=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)


def generate_appengine_service(parent_resource, resource_id=''):
    """Generate appengine service resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'appengine_service'
    cai_resource_name = '//appengine.googleapis.com/apps/{}/services/{}'.format(
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'appengine.googleapis.com/Service'
    resource_data = tmpl.APPENGINE_SERVICE.format(
        APPENGINE_APPLICATION_ID=parent_resource.resource_id,
        APPENGINE_SERVICE_ID=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)


def generate_appengine_version(parent_resource, resource_id=''):
    """Generate appengine version resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id()
    resource_type = 'appengine_version'
    cai_resource_name = '//appengine.googleapis.com/apps/{}/services/{}/versions/{}'.format(
        parent_resource.parent_resource.resource_id,
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'appengine.googleapis.com/Version'
    resource_data = tmpl.APPENGINE_VERSION.format(
        APPENGINE_APPLICATION_ID=parent_resource.parent_resource.resource_id,
        APPENGINE_SERVICE_ID=parent_resource.resource_id,
        VERSION_NUMBER=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)


def generate_compute_firewall_rule(parent_resource, resource_id=''):
    """Generate compute firewall rule resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'compute_firewall_rule'
    cai_resource_name = '//compute.googleapis.com/projects/{}/global/firewalls/{}'.format(
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'compute.googleapis.com/Firewall'
    resource_data = tmpl.COMPUTE_FIREWALL_RULE.format(
        PROJECT_ID=parent_resource.resource_id,
        FIREWALL_RULE_ID=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)


def generate_compute_disk(parent_resource, resource_id=''):
    """Generate compute firewall rule resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'compute_disk'
    cai_resource_name = '//compute.googleapis.com/projects/{}/zones/us-central1-c/disks/{}'.format(
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'compute.googleapis.com/Disk'
    resource_data = tmpl.COMPUTE_DISK.format(
        PROJECT_ID=parent_resource.resource_id,
        DISK_NAME=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)


def generate_compute_snapshot(parent_resource, resource_id=''):
    """Generate compute snapshot resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    resource_id = resource_id if resource_id != '' else _generate_random_id(number_only=False)
    resource_type = 'compute_snapshot'
    cai_resource_name = '//compute.googleapis.com/projects/{}/global/snapshots/{}'.format(
        parent_resource.resource_id,
        resource_id)
    cai_resource_type = 'compute.googleapis.com/Snapshot'
    resource_data = tmpl.COMPUTE_SNAPSHOT.format(
        PROJECT_ID=parent_resource.resource_id,
        SNAPSHOT_ID=resource_id,
        PARENT_CAI_NAME=parent_resource.cai_resource_name)

    return Resource(cai_name=cai_resource_name,
                    cai_type=cai_resource_type,
                    resource_id=resource_id,
                    resource_number=resource_id,
                    resource_type=resource_type,
                    resource_data=resource_data,
                    resource_iam_policy='',
                    parent_resource=parent_resource)



RESOURCE_GENERATOR_FACTORY = {
    'organization': generate_organization,
    'folder': generate_folder,
    'project': generate_project,
    'bucket': generate_bucket,
    'bigquery_dataset': generate_bigquery_dataset,
    'bigquery_table': generate_bigquery_table,
    'service_account': generate_service_account,
    'appengine_application': generate_appengine_application,
    'appengine_service': generate_appengine_service,
    'appengine_version': generate_appengine_version,
    'compute_firewall_rule': generate_compute_firewall_rule,
    'compute_disk': generate_compute_disk,
    'compute_snapshot': generate_compute_snapshot
}

RESOURCE_DEPENDENCY_MAP = {
    'organization': ['folder',
                     'project'],
    'folder': ['project',
               'folder'],
    'project': ['appengine_application',
                'bigquery_dataset',
                'bucket',
                'compute_firewall_rule',
                'compute_disk',
                'compute_snapshot',
                'service_account'],
    'bucket': [],
    'bigquery_dataset': ['bigquery_table'],
    'bigquery_table': [],
    'service_account': [],
    'appengine_application': ['appengine_service'],
    'appengine_service': ['appengine_version'],
    'appengine_version': [],
    'compute_firewall_rule': [],
    'compute_disk': [],
    'compute_snapshot': []
}
