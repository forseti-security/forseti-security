```bash
. ./helpers/setup.sh -p PROJECT_ID -o ORG_ID -k
```

This will create a service account called `cloud-foundation-forseti-<suffix>`,
assign it the necessary roles, and download the service account credentials 
to`${PWD}/credentials.json`.
