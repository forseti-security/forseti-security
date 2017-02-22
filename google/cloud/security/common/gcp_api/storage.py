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

import os
import StringIO

from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.http import MediaIoBaseUpload
from google.cloud.security.common.gcp_api._base_client import _BaseClient
from googleapiclient.errors import HttpError


class StorageClient(_BaseClient):
    """Storage Client."""

    API_NAME = 'storage'

    def __init__(self, credentials=None):
        super(StorageClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)

    def get_bucket_and_path_from(self, full_path):
        """Get the bucket and object path.

        Args:
            full_path: The full GCS path.

        Return:
            The bucket name and object path.
        """
        if not full_path or not full_path.startswith('gs://'):
            raise InvalidBucketPathError(
                'Invalid bucket path: {}'.format(full_path))
        parts = full_path[5:].split('/')
        bucket_name = parts[0]
        bucket_prefix = 5 + len(bucket_name) + 1
        object_path = full_path[bucket_prefix:]
        return bucket_name, object_path

    def put_textfile_object(self, local_file_path, full_bucket_path):
        """Put a text object into a bucket.

        Args:
            full_bucket_path: The full GCS path for the output.
        """ 
        storage_service = self.service
        bucket, object_path = self.get_bucket_and_path_from(full_bucket_path)

        req_body = {
            'name': object_path
        }
        with open(local_file_path, 'rb') as f:
            req = storage_service.objects().insert(
                bucket=bucket,
                body=req_body,
                media_body=MediaIoBaseUpload(
                    f, 'application/octet-stream'))
            resp = req.execute()

    def get_textfile_object(self, full_bucket_path):
        """Gets a text file object as a string.

        Args:
            full_bucket_path: The full path of the bucket object.

        Returns:
            The object's content as a string.
        """
        file_content = ''
        storage_service = self.service
        bucket, object_path = self.get_bucket_and_path_from(full_bucket_path)
        media_request = (storage_service.objects()
                         .get_media(bucket=bucket,
                                    object=object_path))
        try:
            out_stream = StringIO.StringIO()
            downloader = MediaIoBaseDownload(out_stream, media_request)
            done = False
            while done is False:
                _, done = downloader.next_chunk()
            file_content = out_stream.getvalue()
            out_stream.close()
        except HttpError as http_error:
            self.logger.error('Unable to download file: %s', http_error)
            raise http_error
        return file_content
