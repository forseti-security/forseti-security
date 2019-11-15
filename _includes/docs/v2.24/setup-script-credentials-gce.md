```bash
. ./helpers/setup.sh -p PROJECT_ID -o ORG_ID
```

This will create a service account called `cloud-foundation-forseti-<suffix>`,
assign it the proper roles, and download the service account credentials to
`${PWD}/credentials.json`.

Utilizing a shared VPC via a host project is supported with the `-f` flag:

```bash
. ./helpers/setup.sh -p PROJECT_ID -f HOST_PROJECT_ID -o ORG_ID
```

If you are using the Real-Time Enforcer, you will need to generate a
service account with a few extra roles. This can be enabled with the `-e`
flag:

```bash
. ./helpers/setup.sh -p PROJECT_ID -o ORG_ID -e
```
