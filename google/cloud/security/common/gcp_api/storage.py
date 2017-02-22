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

from googleapiclient.http import MediaIoBaseDownload
from google.cloud.security.common.gcp_api._base_client import _BaseClient
from googleapiclient.errors import HttpError


class StorageClient(_BaseClient):
    """Storage Client."""

    API_NAME = 'storage'

    def __init__(self, credentials=None):
        super(StorageClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)

    def get_textfile_object(self, bucket, object_name):
        """Gets a text file object as a string.

        Args:
            bucket: The name of the bucket.
            object_name: The path to the file in Cloud Storage.

        Returns:
            The object's content as a string.
        """
        file_content = ''
        storage_service = self.service
        media_request = (storage_service.objects()
                         .get_media(bucket=bucket,
                                    object=object_name))
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
