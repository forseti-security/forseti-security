---
title: Real-Time Enforcer
order: 106
---
# {{ page.title }}

The Forseti Real-Time Enforcer is an application that uses a Stackdriver log export 
(to a Pub/Sub topic) to trigger policy evaluation and enforcement.

This developer guide for your local environment will walk you through setting
up a [Stackdriver Log Export](https://cloud.google.com/logging/docs/export) 
for your entire organization, filtering for 
[AuditLog](https://cloud.google.com/logging/docs/audit/understanding-audit-logs) 
entries that create or update resources, and sending those log entries 
to a [Pub/Sub topic](https://cloud.google.com/pubsub/docs/overview). 
We will subscribe to that topic and evaluate each incoming log message and 
attempt to map it to a resource that [resource-policy-evaluation-library](https://github.com/forseti-security/resource-policy-evaluation-library) 
(rpe-lib) recognizes. If so, we'll evaluate it with rpe-lib against an 
[Open Policy Agent](https://www.openpolicyagent.org/) instance.

If you prefer to operate on a specific folder or project, the log export 
commands in this document should be altered appropriately.

To deploy the Forseti Real-Time Enforcer on GCP using Terraform, refer to the 
[set up guide]({% link _docs/v2.24/setup/real-time-enforcer.md %}).

## Prerequisites

This guide assumes you have the [Google Cloud SDK](https://cloud.google.com/sdk/) 
installed, and the gcloud binary in your PATH. We also assume that gcloud is 
authenticated as a user (or serviceAccount) with the appropriate permissions.

We'll need to set some environment variables that will be used in later commands. 
We need the Project ID of the Google project we'll be deploying cloud resources into. 
We also need the Organization ID you wish to capture events from 
(See [Retrieving your Organization ID](https://cloud.google.com/resource-manager/docs/creating-managing-organization#retrieving_your_organization_id)).

```
# The project ID of the Google project to deploy the cloud resources into
project_id='my-project-id'
organization_id='000000000000' # The numeric ID of the organization
```

---

## Setting up the GCP resources

### Setting up the Stackdriver log export

First, we'll configure a log export to send specific logs to a Pub/Sub topic. 
In this example, we will export logs from the entire organization so we catch 
events from each project. We will filter for AuditLog entries where the 
severity is not ERROR. We're also filtering out logs from the k8s.io service 
because they're noisy, and any method that includes the string “delete”. 
You can tweak the export and filter to suit your needs.

```
gcloud beta logging sinks create rpe-lib-events \
  pubsub.googleapis.com/projects/$project_id/topics/rpe-lib-events \
  --organization=$organization_id \
  --include-children \
  --log-filter=’logName:”logs/cloudaudit.googleapis.com%2Factivity” severity>INFO’
```

### Setting up the Pub/Sub resources
We now need to create the Pub/Sub topic and subscription, and add an IAM binding 
to allow the log export writer to publish to the topic.

```
# Creating the topic
gcloud pubsub topics create rpe-lib-events --project=$project_id

# Get the writer identity for the log export
writer_id=$(gcloud logging sinks describe rpe-lib-events \
  --project=$project_id \
  --format='value(writerIdentity)'
)

# Add an IAM binding allowing the log writer to publish to our topic
gcloud alpha pubsub topics add-iam-policy-binding rpe-lib-events \
  --member=$writer_id \
  --role=roles/pubsub.publisher \
  --project=$project_id

# Create the subscription our application will use
gcloud pubsub subscriptions create rpe-lib \
  --topic rpe-lib-events \
  --project=$project_id
```

### Setting up application credentials

Our application needs access to subscribe to the Pub/Sub subscription for 
messages, and access to modify resources for policy enforcement. 
With some modification, the example script can be updated to separate 
credentials for the enforcement step, but for simplicity the example uses the 
Application Default Credentials for everything.

```
# Create a new service account for running the application
gcloud iam service-accounts create rpe-lib --project=$project_id

# Create a service account key and save it
gcloud iam service-accounts keys create rpe-lib_credentials.json \
  --iam-account=rpe-lib@$project_id.iam.gserviceaccount.com

# Add policy to access subscription
gcloud beta pubsub subscriptions add-iam-policy-binding rpe-lib \
  --member=serviceAccount:rpe-lib@$project_id.iam.gserviceaccount.com \
  --role=roles/pubsub.subscriber \
  --project=$project_id

# By default, logs will be printed to stdout. If you'd like to send them to stackdriver make sure to add the following permission
# You'll also need to pass the `STACKDRIVER_LOGGING` environment variable to the docker image
gcloud projects add-iam-policy-binding $project_id \
  --role=roles/logging.logWriter \
  --member=serviceAccount:rpe-lib@$project_id.iam.gserviceaccount.com

# Add policy required for enforcement
### Omitting for security reasons. We recommend deciding what policies
### you wish to enforce, and research what permissions are need to enforce them
### for your organization.
```

## Running OPA with our policies

We'll be using the [Open Policy Agent](https://www.openpolicyagent.org/) 
Docker image with policies located in a folder named `policy` found in the 
[resource-policy-evaluation-library Github repository](https://github.com/forseti-security/resource-policy-evaluation-library)
(rpe-lib). You can use your own policies as long as they match the schema used by rpe-lib. 
Refer to the Adding resources and policies for evaluation section for 
documentation on how to add new resources and policies for evaluation.

```
docker run -d \
  --name opa-server \
  -v $(pwd)/policy:/opt/opa/policy \
  openpolicyagent/opa \
  run --server /opt/opa/policy
```

### Building our Docker image
The enforcement code is all in the [run.py](https://github.com/forseti-security/real-time-enforcer/blob/master/app/run.py) 
script of the `real-time-enforcer/app directory`. Stackdriver logs are parsed 
in [real-time-enforcer/app/parsers/stackdriver.py](https://github.com/forseti-security/real-time-enforcer/blob/master/app/parsers/stackdriver.py) 
which attempts to extract the data we need to find a resource in the Google APIs. 
Refer to Adding Resources from Stackdriver section for documentation on how to 
add new resources to be parsed from Stackdriver. After we identify the resource, 
we pass it to rpe-lib and iterate over the violations, remediating them 
one-at-a-time.

A public Docker image is available on [Docker Hub](https://hub.docker.com/r/forsetisecurity/real-time-enforcer) 
which you can use as-is if it suits your needs. Otherwise you can alter the code 
either run it directly or build your own container image to run.

The Docker image is based on the `python:slim` image, and can be built using 
the following command:

```
docker build -t forseti-policy-enforcer .
```

## Running our application
This example uses the public image from [Docker Hub](https://hub.docker.com/r/forsetisecurity/real-time-enforcer), 
and should be altered if you chose to build your own image:

```
docker run -ti --rm \
    --link opa-server \
    -e PROJECT_ID=$project_id \
    -e SUBSCRIPTION_NAME=rpe-lib \
    -e OPA_URL="http://opa-server:8181/v1/data" \
    -e ENFORCE=true \
    -e STACKDRIVER_LOGGING=true \
    -e GOOGLE_APPLICATION_CREDENTIALS=/opt/rpe-lib/etc/credentials.json \
    -v <path_to_credentials_file>:/opt/rpe-lib/etc/credentials.json \
    forsetisecurity/real-time-enforcer
```

## Adding resources from Stackdriver
Add your resource type to the StackdriverLogParser [_extract_asset_info()](https://github.com/forseti-security/real-time-enforcer/blob/8531f53abd3a1ca02af6c2b852a8cc6a188987e1/app/parsers/stackdriver.py#L126) 
function in order to filter for the correct AuditLog resource type message and 
return relevant data about the resource that can be parsed.

Below is an example that adds the `gke_nodepool` resource type, which returns a 
dictionary, “resource_data”, that contains the user relevant properties from 
the AuditLog of a `gke_nodepool` resource.

```       
elif res_type == "gke_nodepool":
            resource_data = {
                'resource_type': 'container.projects.locations.clusters.nodePools',
                'cluster': prop("resource.labels.cluster_name"),
                'name': prop("resource.labels.nodepool_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()
```

Each resource that is then returned is evaluated against the list of available 
policies and enforced if violations are found. These policies can be found in 
the [resource-policy-evaluation-library Github repository](https://github.com/forseti-security/resource-policy-evaluation-library). 
Refer to the Adding resources and policies for evaluation section for 
documentation on how to add new resources and policies for evaluation.

## Adding resources and policies for evaluation

### Resources

The [resource-policy-evaluation-library](https://github.com/forseti-security/resource-policy-evaluation-library) 
(rpe-lib) utilizes the resources found in [rpe/resources/gcp.py](https://github.com/forseti-security/resource-policy-evaluation-library/blob/master/rpe/resources/gcp.py). 
For each resource, define a class object with the following functions defined, 
using the GCP API fields and methods for the resource. 
The base class for resources is [GoogleAPIResource](https://github.com/forseti-security/resource-policy-evaluation-library/blob/258fd3ab517597b4317bff2152357ed743ed6bc5/rpe/resources/gcp.py#L28).

Below is an example of a resource definition:

```
class GcpGkeClusterNodepool(GoogleAPIResource):

    service_name = "container"
    resource_path = "projects.locations.clusters.nodePools"
    version = "v1"
    readiness_key = 'status'
    readiness_value = 'RUNNING'

    required_resource_data = ['name', 'cluster', 'location', 'project_id']

    cai_type = "container.googleapis.com/NodePool"

    def _get_request_args(self):
        return {
            'name': 'projects/{}/locations/{}/clusters/{}/nodePools/{}'.format(
                self._resource_data['project_id'],
                self._resource_data['location'],
                self._resource_data['cluster'],
                self._resource_data['name']
            )
        }

    def _update_request_args(self, body):
        return {
            'name': 'projects/{}/locations/{}/clusters/{}/nodePools/{}'.format(
                self._resource_data['project_id'],
                self._resource_data['location'],
                self._resource_data['cluster'],
                self._resource_data['name']
            ),
            'body': body
        }
```

#### Resource Properties

##### Fields
- **cai_type (str)**: the CAI representation of resource type **(optional)**.
- **get_method (str)**: the API method to retrieve resource. **(Default = “get”)**
- **update_method (str)**: the API method to update resource. **(Default = “update”)**
- **service_name (str)**: the name of the API to call for the resource. 
  - E.g. `container.googleapis.com` becomes `container`
- **readiness_key (str)**: resource field key to check if readiness is defined. 
If a resource is not in a ready state, it cannot be updated. If the resource is 
retrieved and the state changes, updates to the resource will be rejected because 
the ETAG will have changed. Check for a readiness criteria if it exists for a 
resource and wait until the resource is in a ready state to return. **(Default = None)**
  - E.g. “status”
- **readiness_value (str)**: resource field value of the readiness_key that indicates ready state. **(Default = None)**
  - E.g. “RUNNING”
- **readiness_terminal_values (list str)**: resource field values that indicate 
a failed, suspended, or unknown state. Represented as a list of strings. **(Default = None)**
  - E.g. `['FAILED', 'MAINTENANCE', 'SUSPENDED', 'UNKNOWN_STATE']`
- **required_resource_data (list str)**: the fields that are required to be 
retrieved from the get_method for this resource to be parsed and updated. 
Represented as a list of strings. **(Default = [‘name’])**
  - E.g. `['name', 'cluster', 'location', 'project_id']`
- **resource_path (str)**: the REST resource
  - E.g. GKE NodePool resource_path would be `projects.locations.clusters.nodePools`: `https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/projects.locations.clusters.nodePools`
- **version (str)**: version of the API used.
  - E.g. “v1”, “v1beta”

##### Functions
- **_get_request_args()**: Uses the `get_method` of the defined resource to return a dictionary with the properties defined in the body.
- **_update_request_args()**: Uses the `update_method` of the defined resource to remediate/update the resource based on policy evaluation.

Once the resource class has been defined, add it to the `resource_type_map` 
dictionary in the `factory()` function in [rpe/resources/gcp.py](https://github.com/forseti-security/resource-policy-evaluation-library/blob/master/rpe/resources/gcp.py). 
with the `key: value` format as `service_name.resource_path: resource_class`. 
Using the example above, the `key: value` pair would be:
 
```
resource_type_map = {
	...
'container.projects.locations.clusters.nodePools': GcpGkeClusterNodepool,
...
}
```

### Engines

Policy evaluation/enforcement is handled by the Open Policy Agent Engine.

#### Open Policy Agent Engine
The OPA engine evaluates policy against resources using an 
[Open Policy Agent](https://www.openpolicyagent.org/) server. Policies need to 
be namespaced properly for the OPA Engine to locate them and evaluate policy 
properly. 

**Note:** This will not work in cases where policy enforcement is more complicated 
than minor edits to the body of the resource. All remediation is implemented 
in OPA's policy language Rego.

Each unique GCP API should have its own directory with Rego constraints under 
the `policy` directory. For example, to create constraints for the 
`GKE Cluster Nodepool` resource type, look for the container directory, 
as `container.googleapis.com` is the GCP API for this resource type, 
and if it does not exist, create the directory.

For each resource type and desired policy, create a Rego constraint file that 
implements the following rules:

- `valid`: Returns true if the provided input resource adheres to the policy.
- `remediate`: Returns the input resource altered to adhere to policy.
 
The policies should be namespaced as `gcp.<resource.type()>.policy.<policy_name>`. 
For example, the `rpe.resources.gcp.GcpGkeClusterNodepool` resource has a 
type of `container.projects.locations.clusters.nodePools`, so a policy requiring 
auto repairs and auto updates to be enabled might be namespaced 
`gcp.container.projects.locations.clusters.nodePools.policy.auto_repair_upgrade_enabled`.

Below is an example `gke_nodepool_auto_repair_update_enabled.rego` file that 
defines a policy requiring auto repairs and auto updates to be enabled for 
`GKE Cluster Nodepools` by evaluating the resource with the given policy and 
the steps to remediate the resource:

```
package gcp.container.projects.locations.clusters.nodePools.policy.auto_repair_upgrade_enabled

#####
# Resource metadata
#####

labels = input.labels

#####
# Policy evaluation
#####

default valid = false

# Check if node autorepair is enabled
valid = true {
  input.management.autoRepair == true
  input.management.autoUpgrade == true
}

# Check for a global **exclusion based on resource labels
valid = true {
  data.exclusions.label_exclude(labels)
}

#####
# Remediation
#####

remediate = {
  "_remediation_spec": "v2beta1",
  "steps": [
    enable_node_auto_repair_upgrade
  ]
}

enable_node_auto_repair_upgrade = {
    "method": "setManagement",
    "params": {
        "name": combinedName,
        "body":  {
            "name": combinedName,
            "management": {
              "autoRepair": true,
              "autoUpgrade": true
            }
        }
    }
}

# break out the selfLink so we can extract the project, region, cluster and name
selfLinkParts = split(input.selfLink, "/")
# create combined resource name
combinedName = sprintf("projects/%s/locations/%s/clusters/%s/nodePools/%s", [selfLinkParts[5], selfLinkParts[7], selfLinkParts[9], selfLinkParts[11]])
 ```

For each resource type, create a Rego constraint file with a policies rule and 
a violations rule. This allows the OPA engine to query all violations for a 
given resource type in a single API call. 

Below is an example `common.rego` file for the `GKE Cluster Nodepool` resource type:
`package gcp.container.projects.locations.clusters.nodePools`:

```
policies [policy_name] {
    policy := data.gcp.container.projects.locations.clusters.nodePools.policy[policy_name]
}

violations [policy_name] {
    policy := data.gcp.container.projects.locations.clusters.nodePools.policy[policy_name]
    policy.valid != true
}
```

### Relevant links:
- [Real-time Enforcer application source code](https://github.com/forseti-security/real-time-enforcer)
- [Resource-policy-evaluation library (rpe-lib)](https://github.com/forseti-security/resource-policy-evaluation-library)
- [Real-time Enforcer Terraform deployment](https://github.com/forseti-security/terraform-google-forseti/tree/master/modules/real_time_enforcer)
- [Real-time Enforcer Organization Sink deployment](https://github.com/forseti-security/terraform-google-forseti/tree/master/modules/real_time_enforcer_organization_sink)
- [Real-time Enforcer Project Sink deployment](https://github.com/forseti-security/terraform-google-forseti/tree/master/modules/real_time_enforcer_project_sink)
- [Real-time Enforcer Roles Setup deployment](https://github.com/forseti-security/terraform-google-forseti/tree/master/modules/real_time_enforcer_roles)
- [Real-time Enforcer Docker image](https://hub.docker.com/r/forsetisecurity/real-time-enforcer)