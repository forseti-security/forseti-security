```bash
. ./helpers/setup.sh -p PROJECT_ID -o ORG_ID -k
```

This will create a service account called `cloud-foundation-forseti-<suffix>`
and assign it the necessary roles. 

Set and export the `GOOGLE_APPLICATION_CREDENTIALS` variable to the newly
created credential.json as shown below.

`export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"`
