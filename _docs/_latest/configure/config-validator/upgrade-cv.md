---
title: Upgrade Config Validator
order: 703
---

# {{ page.title }}

This page describes how to upgrade Config Validator.

---

## **Upgrade Config Validator**

Follow the steps below to upgrade Config Validator:

- Run the following commands to generate protos for [validator_pb2.py](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/scanner/scanners/config_validator_util/validator_pb2.py)
and [validator_pb2_grpc.py](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/scanner/scanners/config_validator_util/validator_pb2_grpc.py). 
  
  ```
   git clone https://github.com/forseti-security/config-validator.git
  ```

  ```
  cd config-validator
  ```
 
  ```
  make build
  ```
  
  ```
  make pyproto
  ```

- Compare the protos generated in the above step with  [validator_pb2.py](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/scanner/scanners/config_validator_util/validator_pb2.py)
and [validator_pb2_grpc.py](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/scanner/scanners/config_validator_util/validator_pb2_grpc.py) to determine
if protos have changed.

**Note:**
- Changes to the Config Validator Scanner may be required if protos have changed.
- Versions of Config Validator newer than the default value included use OPA 
0.17.x, which is not compatible with some of the policies. Default 
values can be found [here](https://github.com/forseti-security/terraform-google-forseti#inputs).
Please reach out to the [Forseti Security Team](https://forsetisecurity.org/docs/latest/use/get-help.html) 
to see if the specific Config Validator image/tag that you want to you use is 
supported.
