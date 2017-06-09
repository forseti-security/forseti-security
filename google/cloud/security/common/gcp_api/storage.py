# Copyright 2017 Google Inc.
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

from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from googleapiclient import http
from googleapiclient.errors import HttpError

LOGGER = log_util.get_logger(__name__)


def get_bucket_and_path_from(full_path):
    """Get the bucket and object path.

    Args:
        full_path: The full GCS path.

    Return:
        The bucket name and object path.
    """
    if not full_path or not full_path.startswith('gs://'):
        raise api_errors.InvalidBucketPathError(
            'Invalid bucket path: {}'.format(full_path))
    bucket_name = full_path[5:].split('/')[0]
    bucket_prefix = 5 + len(bucket_name) + 1
    object_path = full_path[bucket_prefix:]
    return bucket_name, object_path


class StorageClient(_base_client.BaseClient):
    """Storage Client."""

    API_NAME = 'storage'

    def __init__(self, credentials=None):
        super(StorageClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)
        # Storage API has unlimited rate.

    def put_text_file(self, local_file_path, full_bucket_path):
        """Put a text object into a bucket.

        Args:
            local_file_path: The local path of the file to upload.
            full_bucket_path: The full GCS path for the output.
        """
        storage_service = self.service
        bucket, object_path = get_bucket_and_path_from(
            full_bucket_path)

        req_body = {
            'name': object_path
        }
        with open(local_file_path, 'rb') as f:
            req = storage_service.objects().insert(
                bucket=bucket,
                body=req_body,
                media_body=http.MediaIoBaseUpload(
                    f, 'application/octet-stream'))
            _ = req.execute()

    def get_text_file(self, full_bucket_path):
        """Gets a text file object as a string.

        Args:
            full_bucket_path: The full path of the bucket object.

        Returns:
            The object's content as a string.
        """
        file_content = ''
        storage_service = self.service
        bucket, object_path = get_bucket_and_path_from(
            full_bucket_path)
        media_request = (storage_service.objects()
                         .get_media(bucket=bucket,
                                    object=object_path))
        out_stream = StringIO.StringIO()
        try:
            downloader = http.MediaIoBaseDownload(out_stream, media_request)
            done = False
            while done is False:
                _, done = downloader.next_chunk()
            file_content = out_stream.getvalue()
            out_stream.close()
        except http.HttpError as http_error:
            LOGGER.error('Unable to download file: %s', http_error)
            raise http_error
        return file_content

    def get_buckets(self, project_id):
        """Gets all GCS buckets for a project.

        Args:
            project_id: The project id for a GCP project.

        Returns:
            {
              "kind": "storage#buckets",
              "nextPageToken": string,
              "items": [
                buckets Resource
              ]
            }
        """
        buckets_api = self.service.buckets()
        try:
            buckets_request = buckets_api.list(project=project_id)
            buckets = buckets_request.execute()
            return buckets
        except (HttpError, HttpLib2Error) as e:
            LOGGER.error(api_errors.ApiExecutionError(project_id, e))
            # TODO: pass in "buckets" as resource_name variable
            raise api_errors.ApiExecutionError('buckets', e)

    def get_bucket_acls(self, bucket_name):
        """Gets acls for GCS bucket.

        Args:
            bucket_name: The name of the bucket.

        Returns: ACL json for bucket
        """
        bucket_access_controls_api = self.service.bucketAccessControls()
        bucket_acl_request = bucket_access_controls_api.list(bucket=bucket_name)
        try:
            return bucket_acl_request.execute()
        except (HttpError, HttpLib2Error) as e:
            LOGGER.error(api_errors.ApiExecutionError(bucket_name, e))
            # TODO: pass in "buckets" as resource_name variable
            raise api_errors.ApiExecutionError('buckets', e)
