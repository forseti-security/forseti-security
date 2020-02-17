```bash
. ./helpers/setup.sh -p PROJECT_ID -o ORG_ID -k
```

This will create a service account called `cloud-foundation-forseti-<suffix>`
Grant the newly created service account the following roles:
- roles/container.admin
- roles/container.clusterAdmin
- roles/container.developer
- roles/iam.serviceAccountKey.Admin
- roles/resourcemanager.projectIamAdmin
- roles/compute.networkAdmin

Ensure the following APIs are enabled on the Forseti project:
- container.googleapis.com
- compute.googleapis.com

Set and export the `GOOGLE_APPLICATION_CREDENTIALS` variable to the newly
created credential.json as shown below.

`export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"`
