---
title: Upgrade Config Validator
order: 703
---

# {{ page.title }}

This page describes how to upgrade the Config Validator version used by Forseti. These steps are typically performed by
the Forseti Team to support a new Config Validator version for an upcoming Forseti release.

Not all versions of Config Validator are backwards compatible with Forseti. It is recommended to use the default 
version of Config Validator that is deployed as part of Terraform. Follow the steps on this page to upgrade to a new 
version of Config Validator.

---

## **Generate Config Validator protos**

In order to ensure a version of Config Validator is supported by Forseti, the validator proto files need to be generated
from the branch/tag of Config Validator.

Run the following commands to generate the protos:

  ```
  export CV_VERSION=master
  git clone --branch $CV_VERSION https://github.com/forseti-security/config-validator.git
  cd config-validator
  make build
  make pyproto
  ```

The Python proto files will be created in the `build-grpc` directory of the Config Validator repo. Copy these files to 
the [google/cloud/forseti/scanner/scanners/config_validator_util directory](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/scanner/scanners/config_validator_util) 
in the Forseti repo.

One of the first lines of the [grpc proto](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/scanner/scanners/config_validator_util/validator_pb2_grpc.py)
will need to be updated. Search for `import validator_pb2 as validator__pb2` and replace it with 
`from . import validator_pb2 as validator__pb2`.

## **Policy Library**

Newer versions of Config Validator have more schema validation and might target different versions of Open Policy Agent.
Before deploying a new version of Config Validator with Forseti, ensure that your Policy Library is compatible. It is 
recommended to get the latest versions of the [Policy Library templates](https://github.com/forseti-security/policy-library/tree/master/policies/templates).
Constraints referencing these templates should still be compatible.

## **Testing**

To test Forseti after the Config Validator protos have been added, first run the unit tests:

    ```
    make docker_test_unit
    ```

If all tests pass, then [run Forseti locally]({% link _docs/latest/develop/dev/setup.md %})
along with Config Validator. It's recommended to run Forseti in an IDE (like PyCharm) for debugging and troubleshooting 
purposes. Config Validator can be run with Docker; enter the following commands from the Config Validator cloned repo:
    
    ```
    export POLICY_LIBRARY_DIR=/path/to/policy/library
    make docker_run
    ```

Ensure the Forseti server configuration referenced by PyCharm has the following settings:

    - Enable the Config Validator scanner
    - Disable the [verify policy library feature](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/server_config/templates/configs/forseti_conf_server.yaml.tpl#L240)

When Forseti and Config Validator are both running, run a scan with Forseti and verify there are no errors. Check the 
CloudSQL database to confirm that the violations produced by the scan are correct.

## **Commit Changes**

Create a feature branch and submit a PR to the Forseti repo for the updated protos, along with any other changes. The
Forseti automated tests will run to confirm all parts of Forseti are still working correctly, including Config 
Validator.
