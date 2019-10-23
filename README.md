**branch: master** | **branch: forsetisecurity.org**
:------------ | :------------
[![Build Status](https://travis-ci.org/forseti-security/forseti-security.svg?branch=master)](https://travis-ci.org/forseti-security/forseti-security)|[![Build Status](https://travis-ci.org/forseti-security/forseti-security.svg?branch=forsetisecurity.org)](https://travis-ci.org/forseti-security/forseti-security)
[![codecov](https://codecov.io/gh/forseti-security/forseti-security/branch/master/graph/badge.svg)](https://codecov.io/gh/forseti-security/forseti-security)|


[More info on the branches.](https://forsetisecurity.org/docs/latest/develop/branch-management.html)

# Forseti Security
A community-driven collection of open source tools to improve the security of 
your Google Cloud Platform environments.

[Get Started](https://forsetisecurity.org/docs/latest/setup/install.html)
with Forseti Security.

## Contributing
We are continually improving Forseti Security and invite you to submit feature
requests and bug reports under Issues. If you would like to contribute to our
development efforts, please review our
[contributing guidelines](/.github/CONTRIBUTING.md) and submit a pull request.

### forsetisecurity.org
If you would like to contribute to forsetisecurity.org, the website and its
content are contained in the `forsetisecurity.org` branch. Visit its
[README](https://github.com/forseti-security/forseti-security/tree/forsetisecurity.org)
for instructions on how to make changes.

## Community
Check out our [community page](http://forsetisecurity.org/community/) for ways
to engage with the Forseti Community.

## Integration test
To run integration tests on your local environment without having to 
store sensitive information/secrets in the forseti-security repository, store
project id in TF_VAR_project_id variable, organization id in TF_VAR_org_id, 
domain in TF_VAR_domain, billing account in TF_VAR_billing_account and 
service account key in SERVICE_ACCOUNT_JSON variable.

Run the following command after setting environment variables from bash shell.

```
docker container run -it -e KITCHEN_TEST_BASE_PATH="integration_tests/tests" -e 
SERVICE_ACCOUNT_JSON -e TF_VAR_project_id -e TF_VAR_org_id -e 
TF_VAR_billing_account -e TF_VAR_domain 
-v $(pwd):/workspace gcr.io/cloud-foundation-cicd/cft/developer-tools:0.4.1
/bin/bash
```
