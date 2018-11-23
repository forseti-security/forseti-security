
FAKE_ORG_ID = '1234567890'
FAKE_FOLDER_ID = '987'
FAKE_BILLING_ACCOUNT_ID = '1234-56789'
FAKE_PROJECT_ID = 'forseti-system-test'

GET_TABLES_PAGE_1 = """
{
  "kind": "bigquery#tableList",
  "etag": "6M3sY2P57RlRag1RA5x-vVNSeSo/fuVUqg2afF6rsRcMDFKYmWpN06o",
  "tables": [
  {
    "kind": "bigquery#table",
    "id": "ruihuang-hc-banana:venus_data.venu01s",
    "tableReference": {
    "projectId": "ruihuang-hc-banana",
    "datasetId": "venus_data",
    "tableId": "venu01s"
    },
    "type": "TABLE",
    "creationTime": "1541099822329",
    "expirationTime": "1592939822329"
  },
  {
    "kind": "bigquery#table",
    "id": "ruihuang-hc-banana:venus_data.venu02s",
    "tableReference": {
    "projectId": "ruihuang-hc-banana",
    "datasetId": "venus_data",
    "tableId": "venu02s"
    },
    "type": "TABLE",
    "creationTime": "1542901234400",
    "expirationTime": "1594741234400"
  }
  ],
  "totalItems": 2,
  "nextPageToken": "token1"
}
"""

GET_TABLES_PAGE_2 = """
{
  "kind": "bigquery#tableList",
  "etag": "6M3sY2P57RlRag1RA5x-vVNSeSo/fuVUqg2afF6rsRcMDFKYmWpN06o",
  "tables": [
  {
    "kind": "bigquery#table",
    "id": "ruihuang-hc-banana:venus_data.venu03s",
    "tableReference": {
    "projectId": "ruihuang-hc-banana",
    "datasetId": "venus_data",
    "tableId": "venu03s"
    },
    "type": "TABLE",
    "creationTime": "1541099822329",
    "expirationTime": "1592939822329"
  },
  {
    "kind": "bigquery#table",
    "id": "ruihuang-hc-banana:venus_data.venu04s",
    "tableReference": {
    "projectId": "ruihuang-hc-banana",
    "datasetId": "venus_data",
    "tableId": "venu04s"
    },
    "type": "TABLE",
    "creationTime": "1542901234400",
    "expirationTime": "1594741234400"
  }
  ],
  "totalItems": 2
}
"""

GET_TABLES_RESPONSES = [GET_TABLES_PAGE_1,
                        GET_TABLES_PAGE_2]
