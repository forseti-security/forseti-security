# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Wrapper for Storage API client."""
import json
import StringIO
import urlparse
from googleapiclient import errors
from googleapiclient import http
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import metadata_server

LOGGER = logger.get_logger(__name__)
API_NAME = 'storage'
GCS_SCHEME = 'gs'


def get_bucket_and_path_from(full_path):
    """Get the bucket and object path.

    Args:
        full_path (str): The full GCS path. Must be in the format
            gs://bucket-name/path/to/object

    Returns:
        tuple: The bucket name and object path.
            Ex. (bucket-name, path/to/object)
    Raises:
        InvalidBucketPathError: Raised if the full path cannot be parsed or
            does not look like a GCS bucket URL.
    """
    try:
        parsed = urlparse.urlparse(full_path)
    except AttributeError as e:
        LOGGER.warn('Could not parse path %s: %s', full_path, e)
        parsed = None

    if not parsed or parsed.scheme != GCS_SCHEME:
        raise api_errors.InvalidBucketPathError(
            'Invalid bucket path: {}'.format(full_path))

    bucket_name = parsed.netloc
    object_name = parsed.path[1:]  # Skip leading / in path.
    return bucket_name, object_name


def _get_projectid_from_metadata():
    """Get the current project id from the metadata server, if reachable.

    Returns:
        str: The current project id or None if the metadata server is
            unreachable.
    """
    if metadata_server.can_reach_metadata_server():
        return metadata_server.get_project_id()
    return None


def _user_project_missing_error(error):
    """Parses the error and checks if it is a no user project exception.

    Args:
        error (Exception): The error message to check.

    Returns:
        bool: True if this is a user project missing error, else False.
    """
    if isinstance(error, errors.HttpError):
        if (error.resp.status == 400 and
                error.resp.get('content-type', '').startswith(
                    'application/json')):
            error_details = json.loads(error.content.decode('utf-8'))
            all_errors = error_details.get('error', {}).get('errors', [])
            user_project_required_errors = [
                err for err in all_errors
                if (err.get('domain', '') == 'global' and
                    err.get('reason', '') == 'required')
            ]
            if (user_project_required_errors and
                    len(user_project_required_errors) == len(all_errors)):
                return True
    return False


class StorageRepositoryClient(_base_repository.BaseRepositoryClient):
    """Storage API Respository."""

    def __init__(self,
                 credentials=None,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            credentials (GoogleCredentials): An optional GoogleCredentials
                object to use.
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to limit the requests within.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._buckets = None
        self._bucket_acls = None
        self._default_object_acls = None
        self._objects = None
        self._object_acls = None

        super(StorageRepositoryClient, self).__init__(
            API_NAME, versions=['v1'],
            credentials=credentials,
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def buckets(self):
        """An _StorageBucketsRepository instance."""
        if not self._buckets:
            self._buckets = self._init_repository(
                _StorageBucketsRepository)
        return self._buckets

    @property
    def bucket_acls(self):
        """An _StorageBucketAclsRepository instance."""
        if not self._bucket_acls:
            self._bucket_acls = self._init_repository(
                _StorageBucketAclsRepository)
        return self._bucket_acls

    @property
    def default_object_acls(self):
        """An _StorageDefaultObjectAclsRepository instance."""
        if not self._default_object_acls:
            self._default_object_acls = self._init_repository(
                _StorageDefaultObjectAclsRepository)
        return self._default_object_acls

    @property
    def objects(self):
        """An _StorageObjectsRepository instance."""
        if not self._objects:
            self._objects = self._init_repository(
                _StorageObjectsRepository)
        return self._objects

    @property
    def object_acls(self):
        """An _StorageObjectAclsRepository instance."""
        if not self._object_acls:
            self._object_acls = self._init_repository(
                _StorageObjectAclsRepository)
        return self._object_acls
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _StorageBucketsRepository(
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Storage Buckets repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_StorageBucketsRepository, self).__init__(
            component='buckets', **kwargs)

    # Extend the base get_iam_policy implementation to support buckets.
    # pylint: disable=arguments-differ
    def get_iam_policy(self, bucket, fields=None, **kwargs):
        """Get Bucket IAM Policy.

        Args:
            bucket (str): The id of the bucket to fetch.
            fields (str): Fields to include in the response - partial response.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: GCE response.
        """
        # The Buckets getIamPolicy does not allow the 'body' argument, so this
        # overrides the default behavior by setting include_body to False. It
        # also takes a bucket id instead of a resource path.
        return repository_mixins.GetIamPolicyQueryMixin.get_iam_policy(
            self, bucket, fields=fields, include_body=False,
            resource_field='bucket', **kwargs)
    # pylint: enable=arguments-differ


class _StorageBucketAclsRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Storage Bucket Access Controls repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_StorageBucketAclsRepository, self).__init__(
            component='bucketAccessControls', list_key_field='bucket', **kwargs)


class _StorageDefaultObjectAclsRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Storage Default Object Access Controls repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_StorageDefaultObjectAclsRepository, self).__init__(
            component='defaultObjectAccessControls', list_key_field='bucket',
            **kwargs)


class _StorageObjectsRepository(
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Iam Projects ServiceAccounts repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_StorageObjectsRepository, self).__init__(
            key_field='bucket', component='objects', **kwargs)

    # Extend the base get_iam_policy implementation to support objects.
    # pylint: disable=arguments-differ
    def get_iam_policy(self, bucket, object_name, fields=None, **kwargs):
        """Get Object IAM Policy.

        Args:
            bucket (str): The name of the bucket to fetch.
            object_name (str): The name of the object to fetch.
            fields (str): Fields to include in the response - partial response.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: GCE response.
        """
        # The Objects getIamPolicy does not allow the 'body' argument, so this
        # overrides the default behavior by setting include_body to False. It
        # also takes a bucket id and object id instead of a resource path.
        return repository_mixins.GetIamPolicyQueryMixin.get_iam_policy(
            self, bucket, fields=fields, include_body=False,
            resource_field='bucket', object=object_name, **kwargs)
    # pylint: enable=arguments-differ

    def download(self, bucket, object_name):
        """Download an object from a bucket.

        Args:
            bucket (str): The name of the bucket to read from.
            object_name (str): The name of the object to read.

        Returns:
            str: The contents of the object.
        """
        verb_arguments = {
            'bucket': bucket,
            'object': object_name}

        media_request = self._build_request('get_media', verb_arguments)
        media_request.http = self.http

        file_content = ''
        out_stream = StringIO.StringIO()
        try:
            downloader = http.MediaIoBaseDownload(out_stream, media_request)
            done = False
            while not done:
                _, done = downloader.next_chunk(num_retries=self._num_retries)
            file_content = out_stream.getvalue()
        finally:
            out_stream.close()
        return file_content

    def download_to_file(self, bucket, object_name, output_file):
        """Download an object from a bucket.

         Args:
            bucket (str): The name of the bucket to read from.
            object_name (str): The name of the object to read.
            output_file (file): The file object to write the data to.

         Returns:
            int: Total size in bytes of file.
        """
        verb_arguments = {
            'bucket': bucket,
            'object': object_name}

        media_request = self._build_request('get_media', verb_arguments)
        media_request.http = self.http

        downloader = http.MediaIoBaseDownload(output_file, media_request)
        done = False
        while not done:
            progress, done = downloader.next_chunk(
                num_retries=self._num_retries)
        return progress.total_size

    def upload(self, bucket, object_name, file_content):
        """Upload an object to a bucket.

        Args:
            bucket (str): The id of the bucket to insert into.
            object_name (str): The name of the object to write.
            file_content (file): An open file object of the content to write to
                the object.

        Returns:
            dict: The resource metadata for the object.
        """
        body = {
            'name': object_name
        }
        verb_arguments = {
            'bucket': bucket,
            'body': body,
            'media_body': http.MediaIoBaseUpload(file_content,
                                                 'application/octet-stream'),
        }
        return self.execute_command(verb='insert',
                                    verb_arguments=verb_arguments)


class _StorageObjectAclsRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Storage Object Access Controls repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_StorageObjectAclsRepository, self).__init__(
            component='objectAccessControls', list_key_field='bucket', **kwargs)


class StorageClient(object):
    """Storage Client."""

    def __init__(self, *args, **kwargs):
        """Initialize.

        Args:
            *args (dict): Default args passed to all API Clients, not used by
                the StorageClient.
            **kwargs (dict): The kwargs.
        """
        del args
        # Storage API has unlimited rate.
        if 'user_project' in kwargs:
            self._user_project = kwargs['user_project']
        else:
            self._user_project = _get_projectid_from_metadata()

        self.repository = StorageRepositoryClient(
            credentials=kwargs.get('credentials'),
            quota_max_calls=None,
            use_rate_limiter=False)

    def put_text_file(self, local_file_path, full_bucket_path):
        """Put a text object into a bucket.

        Args:
            local_file_path (str): The local path of the file to upload.
            full_bucket_path (str): The full GCS path for the output.

        Returns:
            dict: The uploaded object's resource metadata.
        """
        bucket, object_name = get_bucket_and_path_from(
            full_bucket_path)

        with open(local_file_path, 'rb') as f:
            results = self.repository.objects.upload(bucket, object_name, f)
            LOGGER.debug('Putting a text object into a bucket, local_file_path'
                         ' = %s, full_bucket_path = %s, results = %s',
                         local_file_path, full_bucket_path, results)
            return results

    def get_text_file(self, full_bucket_path):
        """Gets a text file object as a string.

        Args:
            full_bucket_path (str): The full path of the bucket object.

        Returns:
            str: The object's content as a string.

        Raises:
            HttpError: HttpError is raised if the call to the GCP storage API
                fails
        """
        bucket, object_name = get_bucket_and_path_from(full_bucket_path)
        try:
            results = self.repository.objects.download(bucket, object_name)
            LOGGER.debug('Getting a text file object as a string,'
                         ' full_bucket_path = %s, results = %s',
                         full_bucket_path, results)
            return results
        except errors.HttpError:
            LOGGER.exception('Unable to download file.')
            raise

    def download(self, full_bucket_path, output_file):
        """Downloads a copy of a file from GCS.

         Args:
            full_bucket_path (str): The full path of the bucket object.
            output_file (file): The file object to write the data to.

         Returns:
            int: Total size in bytes of file.

         Raises:
            HttpError: HttpError is raised if the call to the GCP storage API
                fails
        """
        bucket, object_name = get_bucket_and_path_from(full_bucket_path)
        try:
            file_size = self.repository.objects.download_to_file(
                bucket, object_name, output_file)
            LOGGER.debug('Downloading file object, full_bucket_path = %s, '
                         'total size = %i', full_bucket_path, file_size)
            return file_size
        except errors.HttpError:
            LOGGER.exception('Unable to download file.')
            raise

    def get_buckets(self, project_id):
        """Gets all GCS buckets for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            list: a list of bucket resource dicts.
            https://cloud.google.com/storage/docs/json_api/v1/buckets

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            paged_results = self.repository.buckets.list(project_id,
                                                         projection='full')
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'items')
            LOGGER.debug('Getting all GCS buckets for a project, project_id ='
                         ' %s, flattened_results = %s',
                         project_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'buckets', e, 'project_id', project_id)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_bucket_acls(self, bucket, user_project=None):
        """Gets acls for GCS bucket.

        Args:
            bucket (str): The name of the bucket.
            user_project (str): The user project to bill the bucket access to,
                for requester pays buckets.

        Returns:
            dict: ACL json for bucket

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            kwargs = {}
            if user_project:
                kwargs['userProject'] = user_project
            results = self.repository.bucket_acls.list(resource=bucket,
                                                       **kwargs)
            flattened_results = api_helpers.flatten_list_results(results,
                                                                 'items')
            LOGGER.debug('Getting acls for a GCS Bucket, bucket = %s,'
                         ' flattened_results = %s',
                         bucket, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            if not user_project and _user_project_missing_error(e):
                if self._user_project:
                    LOGGER.info('User project required for bucket %s, '
                                'retrying.', bucket)
                    return self.get_bucket_acls(bucket, self._user_project)

            api_exception = api_errors.ApiExecutionError(
                'bucketAccessControls', e, 'bucket', bucket)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_bucket_iam_policy(self, bucket, user_project=None):
        """Gets the IAM policy for a bucket.

        Args:
            bucket (str): The bucket to fetch the policy for.
            user_project (str): The user project to bill the bucket access to,
                for requester pays buckets.

        Returns:
            dict: The IAM policies for the bucket.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            kwargs = {}
            if user_project:
                kwargs['userProject'] = user_project
            results = self.repository.buckets.get_iam_policy(bucket, **kwargs)
            LOGGER.debug('Getting the IAM policy for a bucket, bucket = %s,'
                         ' results = %s', bucket, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            if not user_project and _user_project_missing_error(e):
                if self._user_project:
                    LOGGER.info('User project required for bucket %s, '
                                'retrying.', bucket)
                    return self.get_bucket_iam_policy(bucket,
                                                      self._user_project)

            api_exception = api_errors.ApiExecutionError(
                'bucketIamPolicy', e, 'bucket', bucket)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_default_object_acls(self, bucket, user_project=None):
        """Gets acls for GCS bucket.

        Args:
            bucket (str): The name of the bucket.
            user_project (str): The user project to bill the bucket access to,
                for requester pays buckets.

        Returns:
            dict: ACL json for bucket

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            kwargs = {}
            if user_project:
                kwargs['userProject'] = user_project
            results = self.repository.default_object_acls.list(resource=bucket,
                                                               **kwargs)
            flattened_results = api_helpers.flatten_list_results(results,
                                                                 'items')
            LOGGER.debug('Getting default object acls for GCS bucket, bucket'
                         ' = %s, flattened_results = %s',
                         bucket, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            if not user_project and _user_project_missing_error(e):
                if self._user_project:
                    LOGGER.info('User project required for bucket %s, '
                                'retrying.', bucket)
                    return self.get_default_object_acls(bucket,
                                                        self._user_project)

            api_exception = api_errors.ApiExecutionError(
                'defaultObjectAccessControls', e, 'bucket', bucket)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_objects(self, bucket, user_project=None):
        """Gets all objects in a bucket.

        Args:
            bucket (str): The bucket to list to objects in.
            user_project (str): The user project to bill the bucket access to,
                for requester pays buckets.

        Returns:
            list: a list of object resource dicts.
            https://cloud.google.com/storage/docs/json_api/v1/objects

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            kwargs = {}
            if user_project:
                kwargs['userProject'] = user_project
            paged_results = self.repository.objects.list(bucket,
                                                         projection='full',
                                                         **kwargs)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'items')
            LOGGER.debug('Getting all the objects in a bucket, bucket = %s,'
                         ' flattened_results = %s',
                         bucket, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            if not user_project and _user_project_missing_error(e):
                if self._user_project:
                    LOGGER.info('User project required for bucket %s, '
                                'retrying.', bucket)
                    return self.get_objects(bucket, self._user_project)

            api_exception = api_errors.ApiExecutionError(
                'objects', e, 'bucket', bucket)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_object_acls(self, bucket, object_name, user_project=None):
        """Gets acls for GCS object.

        Args:
            bucket (str): The name of the bucket.
            object_name (str): The name of the object.
            user_project (str): The user project to bill the bucket access to,
                for requester pays buckets.


        Returns:
            dict: ACL json for bucket

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            kwargs = {}
            if user_project:
                kwargs['userProject'] = user_project
            results = self.repository.object_acls.list(resource=bucket,
                                                       object=object_name,
                                                       **kwargs)
            flattened_results = api_helpers.flatten_list_results(results,
                                                                 'items')
            LOGGER.debug('Getting acls for GCS object, bucket = %s,'
                         ' object_name = %s, flattened_results = %s',
                         bucket, object_name, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            if not user_project and _user_project_missing_error(e):
                if self._user_project:
                    LOGGER.info('User project required for bucket %s, '
                                'retrying.', bucket)
                    return self.get_object_acls(bucket, object_name,
                                                self._user_project)

            api_exception = api_errors.ApiExecutionError(
                'objectAccessControls', e, 'bucket', bucket)
            LOGGER.exception(api_exception)
            raise api_exception

    def get_object_iam_policy(self, bucket, object_name, user_project=None):
        """Gets the IAM policy for an object.

        Args:
            bucket (str): The bucket to fetch the policy for.
            object_name (str): The object name to fetch the policy for.
            user_project (str): The user project to bill the bucket access to,
                for requester pays buckets.

        Returns:
            dict: The IAM policies for the object.

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails
        """
        try:
            kwargs = {}
            if user_project:
                kwargs['userProject'] = user_project
            results = self.repository.objects.get_iam_policy(bucket,
                                                             object_name,
                                                             **kwargs)
            LOGGER.debug('Getting the IAM policy for an object, bucket = %s,'
                         ' object_name = %s, results = %s',
                         bucket, object_name, results)
            return results
        except (errors.HttpError, HttpLib2Error) as e:
            if not user_project and _user_project_missing_error(e):
                if self._user_project:
                    LOGGER.info('User project required for bucket %s, '
                                'retrying.', bucket)
                    return self.get_object_iam_policy(bucket, object_name,
                                                      self._user_project)

            api_exception = api_errors.ApiExecutionError(
                'objectIamPolicy', e, 'bucket', bucket)
            LOGGER.exception(api_exception)
            raise api_exception
