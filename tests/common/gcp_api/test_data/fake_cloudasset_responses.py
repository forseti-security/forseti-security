# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Test data for CloudAsset API responses."""

FOLDER = "folders/5678901234"
PROJECT = "projects/1234567890"
ORGANIZATION = "organizations/9876543210"
FOLDER_OPERATION = "folders/5678901234/operations/ExportAssets/RESOURCE/123456789098765"
PROJECT_OPERATION = "projects/1234567890/operations/ExportAssets/RESOURCE/123456789098765"
ORGANIZATION_OPERATION = "organizations/9876543210/operations/ExportAssets/RESOURCE/567890987654321"

DESTINATION = "gs://forseti-test-bucket/test-export.txt"

ASSET_TYPES = ["cloudresourcemanager.googleapis.com/Project"]

EXPORT_ASSETS_FOLDER_RESOURCES_OPERATION = """
{
  "name": "folders/5678901234/operations/ExportAssets/RESOURCE/123456789098765",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "folders/5678901234",
    "assetTypes": [
      "cloudresourcemanager.googleapis.com/Project"
    ],
    "contentType": "RESOURCE",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  }
}
"""

EXPORT_ASSETS_FOLDER_RESOURCES_DONE = """
{
  "name": "folders/5678901234/operations/ExportAssets/RESOURCE/123456789098765",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "folders/5678901234",
    "assetTypes": [
      "cloudresourcemanager.googleapis.com/Project"
    ],
    "contentType": "RESOURCE",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  },
  "done": true,
  "response": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsResponse",
    "readTime": "2018-09-14T01:48:44.507918774Z",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  }
}
"""

EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION = """
{
  "name": "projects/1234567890/operations/ExportAssets/123456789098765",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "projects/1234567890",
    "contentType": "RESOURCE",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  }
}
"""

EXPORT_ASSETS_PROJECT_RESOURCES_DONE = """
{
  "name": "projects/1234567890/operations/ExportAssets/123456789098765",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "projects/1234567890",
    "contentType": "RESOURCE",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  },
  "done": true,
  "response": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsResponse",
    "readTime": "2018-09-14T01:48:44.507918774Z",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  }
}
"""

EXPORT_ASSETS_ORGANIZATION_RESOURCES_OPERATION = """
{
  "name": "organizations/9876543210/operations/ExportAssets/567890987654321",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "organizations/9876543210",
    "asset_types": [
     "cloudresourcemanager.googleapis.com/Project"
    ],
    "contentType": "RESOURCE",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  }
}
"""

EXPORT_ASSETS_ORGANIZATION_RESOURCES_DONE = """
{
  "name": "organizations/9876543210/operations/ExportAssets/567890987654321",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "organizations/9876543210",
    "asset_types": [
     "cloudresourcemanager.googleapis.com/Project"
    ],
    "contentType": "RESOURCE",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  },
  "done": true,
  "response": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsResponse",
    "readTime": "2018-09-14T01:48:44.507918774Z",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  }
}
"""

EXPORT_ASSETS_ERROR = """
{
  "name": "organizations/9876543210/operations/ExportAssets/567890987654321",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "organizations/9876543210",
    "contentType": "IAM_POLICY",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  },
  "done": true,
  "error": {
    "code": 13,
    "message": "Snapshot or asset write failed"
  }
}
"""

PERMISSION_DENIED = """
{
  "error": {
    "code": 403,
    "message": "The caller does not have permission",
    "status": "PERMISSION_DENIED",
  }
}
"""
