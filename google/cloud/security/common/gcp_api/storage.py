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
import StringIO
import urlparse
from googleapiclient import errors
from googleapiclient import http
from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import api_helpers
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import repository_mixins
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)

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


class StorageRepositoryClient(_base_repository.BaseRepositoryClient):
    """Storage API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to limit the requests within.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._objects = None
        self._buckets = None

        super(StorageRepositoryClient, self).__init__(
            'storage', versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    @property
    def buckets(self):
        """An _StorageBucketsRepository instance.

        Returns:
            object: An _StorageBucketsRepository instance.
        """
        if not self._buckets:
            self._buckets = self._init_repository(
                _StorageBucketsRepository)
        return self._buckets

    @property
    def objects(self):
        """An _StorageObjectsRepository instance.

        Returns:
            object: An _StorageObjectsRepository instance.
        """
        if not self._objects:
            self._objects = self._init_repository(
                _StorageObjectsRepository)
        return self._objects


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
                _, done = downloader.next_chunk()
            file_content = out_stream.getvalue()
        finally:
            out_stream.close()
        return file_content

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


class StorageClient(object):
    """Storage Client."""

    def __init__(self, *args, **kwargs):
        """Initialize.

        Args:
            *args (dict): Default args passed to all API Clients, not used by
                the StorageClient.
            **kwargs (dict): The kwargs.
        """
        del args, kwargs
        # Storage API has unlimited rate.
        self.repository = StorageRepositoryClient(
            quota_max_calls=0,
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
            return self.repository.objects.upload(bucket, object_name, f)

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
            return self.repository.objects.download(bucket, object_name)
        except errors.HttpError as e:
            LOGGER.error('Unable to download file: %s', e)
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
                GCP ClodSQL API fails
        """
        try:
            paged_results = self.repository.buckets.list(project_id,
                                                         projection='full')
            return api_helpers.flatten_list_results(paged_results, 'items')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError('buckets', e)

    def get_bucket_iam_policy(self, bucket):
        """Gets the IAM policy for a bucket.

        Args:
            bucket (str): The bucket to fetch the policy for.

        Returns:
            dict: The IAM policies for the bucket.
        """
        try:
            return self.repository.buckets.get_iam_policy(bucket)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(bucket, e))
            raise api_errors.ApiExecutionError('bucketIamPolicy', e)

    def get_objects(self, bucket):
        """Gets all GCS buckets for a project.

        Args:
            bucket (str): The bucket to list to objects in.

        Returns:
            list: a list of object resource dicts.
            https://cloud.google.com/storage/docs/json_api/v1/objects

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP ClodSQL API fails
        """
        try:
            paged_results = self.repository.objects.list(bucket,
                                                         projection='full')
            return api_helpers.flatten_list_results(paged_results, 'items')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(bucket, e))
            raise api_errors.ApiExecutionError('objects', e)

    def get_object_iam_policy(self, bucket, object_name):
        """Gets the IAM policy for an object.

        Args:
            bucket (str): The bucket to fetch the policy for.
            object_name (str): The object name to fetch the policy for.

        Returns:
            dict: The IAM policies for the object.
        """
        try:
            return self.repository.objects.get_iam_policy(bucket, object_name)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(bucket, e))
            raise api_errors.ApiExecutionError('objectIamPolicy', e)
