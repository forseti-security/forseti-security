FAKE_IAM_MEMBERS = [
    "allUsers",
    "allAuthenticatedUsers"
    "domain:test-domain.com",
    "group:test-group-1@my-domain-123.com",
    "group:test-group-2@my-domain-123.com",
    "group:test-group-3@my-domain-123.com",
    "serviceAccount:test-sa-1@this-is-my-project.gserviceaccount.com",
    "serviceAccount:test-sa-2@this-is-my-project.gserviceaccount.com",
    "serviceAccount:test-sa-3@this-is-my-project.gserviceaccount.com",
    "serviceAccount:test-sa-4@this-is-my-project.gserviceaccount.com",
    "user:test-user-1@my-domain-123.com",
    "user:test-user-2@my-domain-123.com",
    "user:test-user-3@my-domain-123.com",
]

ORGANIZATION_ROLES = [
    'roles/role111',
    'roles/role112',
    'roles/role113',
    'roles/role114',
    'roles/role115',
    'roles/role116',
    'roles/role117',
    'roles/role118',
    'roles/role119',
    'roles/role110',
]

_FOLDER_ROLES = [
    'roles/role221',
    'roles/role222',
    'roles/role223',
    'roles/role224',
]
FOLDER_ROLES = ORGANIZATION_ROLES[:]
FOLDER_ROLES.extend(_FOLDER_ROLES)


_PROJECT_ROLES = [
    'roles/role331',
    'roles/role332',
    'roles/role333',
    'roles/role334',

]
PROJECT_ROLES = FOLDER_ROLES[:]
PROJECT_ROLES.extend(_PROJECT_ROLES)


BUCKET_ROLES = [
    'roles/bucket1',
    'roles/bucket2',
    'roles/bucket3'
]

BIGQUERY_ROLES = [
    'roles/bigquery1',
    'roles/bigquery2',
    'roles/bigquery3'
]

SERVICE_ACCOUNT_ROLES = [
    'roles/serviceaccount1',
    'roles/serviceaccount2',
    'roles/serviceaccount3'
]


# IAM Policy params: CAI_RESOURCE_NAME, CAI_RESOURCE_TYPE AND IAM_BINDING.
IAM_POLICY = '''
{{
    "name":"{CAI_RESOURCE_NAME}",
    "asset_type":"{CAI_RESOURCE_TYPE}",
    "iam_policy":{{
        "etag":"BwVPk6g/3yI=",
        "bindings":{IAM_BINDING}
    }}
}}
'''


# IAM Binding params: ROLE and MEMBER_LIST
IAM_BINDING = '''
{{
    "role":"{ROLE}",
    "members":{MEMBER_LIST}
}}
'''


# Org params: ORGANIZATION_NUMBER and DISPLAY_NAME
ORGANIZATION = '''
{{
    "name":"//cloudresourcemanager.googleapis.com/organizations/{ORGANIZATION_NUMBER}",
    "asset_type":"cloudresourcemanager.googleapis.com/Organization",
    "resource": {{
        "version":"v1beta1",
        "discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v1beta1",
        "discovery_name":"Organization",
        "data":{{
            "creationTime":"2016-09-02T18:55:58.783Z",
            "displayName":"{DISPLAY_NAME}","lastModifiedTime":"2017-02-14T05:43:45.012Z",
            "lifecycleState":"ACTIVE","name":"organizations/{ORGANIZATION_NUMBER}",
            "organizationId":"{ORGANIZATION_NUMBER}",
            "owner":{{
                "directoryCustomerId":"abc123abc"
            }}
        }}
    }}
}}
'''

# Folder params: FOLDER_NUMBER, PARENT_CAI_NAME, DISPLAY_NAME, PARENT_TYPE and PARENT_ID
FOLDER = '''
{{
    "name":"//cloudresourcemanager.googleapis.com/folders/{FOLDER_NUMBER}",
    "asset_type":"cloudresourcemanager.googleapis.com/Folder",
    "resource":{{
        "version":"v2alpha1","discovery_document_uri":
        "https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v2alpha1",
        "discovery_name":"Folder","parent":"{PARENT_CAI_NAME}",
        "data":{{
            "createTime":"2019-05-10T20:56:44.244Z",
            "displayName":"{DISPLAY_NAME}",
            "lifecycleState":"ACTIVE",
            "name":"folders/{FOLDER_NUMBER}","parent":"{PARENT_ID}"
        }}
    }}
}}
'''

# Project params: PROJECT_NUMBER, PROJECT_ID, PARENT_CAI_NAME, DISPLAY_NAME, PARENT_TYPE and PARENT_ID
PROJECT = '''
{{
    "name":"//cloudresourcemanager.googleapis.com/projects/{PROJECT_NUMBER}",
    "asset_type":"cloudresourcemanager.googleapis.com/Project",
    "resource":{{
        "version":"v1beta1",
        "discovery_document_uri":"https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v1beta1",
        "discovery_name":"Project","parent":"{PARENT_CAI_NAME}",
        "data":{{
            "createTime":"2019-03-13T19:07:20.987Z",
            "lifecycleState":"ACTIVE",
            "name":"{DISPLAY_NAME}",
            "parent":{{
                "id":"{PARENT_ID}",
                "type":"{PARENT_TYPE}"
            }},
            "projectId":"{PROJECT_ID}","projectNumber":"{PROJECT_NUMBER}"
        }}
    }}
}}
'''

# Bucket params: BUCKET_ID, PARENT_CAI_NAME and PARENT_ID
BUCKET = '''
{{
    "name":"//storage.googleapis.com/{BUCKET_ID}",
    "asset_type":"storage.googleapis.com/Bucket",
    "resource":{{
        "version":"v1",
        "discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/storage/v1/rest",
        "discovery_name":"Bucket",
        "parent":"{PARENT_CAI_NAME}",
        "data":{{
            "acl":[],
            "billing":{{}},
            "cors":[],
            "defaultObjectAcl":[],
            "encryption":{{}},
            "etag":"CAI=",
            "iamConfiguration":{{
                "bucketPolicyOnly":{{"enabled":false}},
                "uniformBucketLevelAccess":{{"enabled":false}}
            }},
            "id":"{BUCKET_ID}",
            "kind":"storage#bucket",
            "labels":{{"goog-dm":"{BUCKET_ID}"}},
            "lifecycle":{{"rule":[]}},
            "location":"US-CENTRAL1",
            "locationType":"region",
            "logging":{{}},
            "metageneration":2,
            "name":"{BUCKET_ID}",
            "owner":{{}},
            "projectNumber":{PARENT_ID},
            "retentionPolicy":{{}},
            "selfLink":"https://www.googleapis.com/storage/v1/b/{BUCKET_ID}","storageClass":"STANDARD",
            "timeCreated":"2019-03-13T19:22:22.504Z","updated":"2019-03-13T19:22:23.656Z",
            "versioning":{{}},"website":{{}}
        }}
    }}
}}
'''

# BigQuery Dataset params: DATASET_ID, PARENT_CAI_NAME, PROJECT_ID, LOCATION
BIGQUERY_DATASET = '''
{{
    "name":"//bigquery.googleapis.com/projects/{PROJECT_ID}/datasets/{DATASET_ID}",
    "asset_type":"bigquery.googleapis.com/Dataset",
    "resource":{{
        "version":"v2",
        "discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/bigquery/v2/rest",
        "discovery_name":"Dataset",
        "parent":"{PARENT_CAI_NAME}",
        "data":{{
            "creationTime":"1562042780892",
            "datasetReference":{{
                "datasetId":"{DATASET_ID}",
                "projectId":"{PROJECT_ID}"
            }},
            "id":"{PROJECT_ID}:{DATASET_ID}",
            "kind":"bigquery#dataset",
            "lastModifiedTime":"1562042780892",
            "location":"{LOCATION}"
        }}
    }}
}}
'''

# BigQuery Table params: PROJECT_ID, DATASET_ID, TABLE_ID and PARENT_CAI_NAME
BIGQUERY_TABLE = '''
{{
    "name":"//bigquery.googleapis.com/projects/{PROJECT_ID}/datasets/{DATASET_ID}/tables/{TABLE_ID}",
    "asset_type":"bigquery.googleapis.com/Table",
    "resource":{{
        "version":"v2",
        "discovery_document_uri":"https://www.googleapis.com/discovery/v1/apis/bigquery/v2/rest",
        "discovery_name":"Table",
        "parent":"{PARENT_CAI_NAME}",
        "data":{{
            "creationTime":"1517582269482",
            "expirationTime":"0",
            "id":"{PROJECT_ID}:{DATASET_ID}.{TABLE_ID}",
            "kind":"bigquery#table",
            "schema":{{
                "fields":[{{
                    "description":"",
                    "name":"name",
                    "type":"TYPE_STRING"
                }}]
            }},
            "tableReference":{{
                "datasetId":"{DATASET_ID}",
                "projectId":"{PROJECT_ID}",
                "tableId":"{TABLE_ID}"
            }}
        }}
    }}
}}
'''

# Service Account params: PROJECT_ID, DISPLAY_NAME, PARENT_CAI_NAME and SERVICE_ACCOUNT_ID.
SERVICE_ACCOUNT = '''
{{
    "name":"//iam.googleapis.com/projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_ID}",
    "asset_type":"iam.googleapis.com/ServiceAccount",
    "resource":{{
        "version":"v1",
        "discovery_document_uri":"https://iam.googleapis.com/$discovery/rest",
        "discovery_name":"ServiceAccount",
        "parent":"{PARENT_CAI_NAME}",
        "data":{{
            "displayName":"{DISPLAY_NAME}",
            "email":"{SERVICE_ACCOUNT_ID}@{PROJECT_ID}.iam.gserviceaccount.com",
            "name":"projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_ID}@{PROJECT_ID}.iam.gserviceaccount.com",
            "oauth2ClientId":"22222222222222222222",
            "projectId":"{PROJECT_ID}",
            "uniqueId":"11111111111111111111"
        }}
    }}
}}
'''




