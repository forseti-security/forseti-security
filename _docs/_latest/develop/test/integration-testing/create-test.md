---
title: Create Tests
order: 044
---

# {{ page.title }}

This page describes how to add integration tests for your Forseti contributions.

---
## **Overview**

The tech stack used to run Forseti integration tests consists of Kitchen, Kitchen 
Terraform, InSpec and Google Cloud Build.

[Kitchen](https://kitchen.ci/) provides a test harness to execute infrastructure 
code on one or more platforms in isolation. It supports many testing frameworks 
out of the box including InSpec.

[Kitchen-Terraform](https://github.com/newcontext-oss/kitchen-terraform) is an 
open source set of Test-Kitchen plugins for testing Terraform configuration. It 
is a tool that lets us test Terraform modules using InSpec. 

[InSpec](https://www.inspec.io/) is a free and open-source framework for testing 
and auditing applications and infrastructure. InSpec works by comparing the 
actual state of the system with the desired state expressed in InSpec code. It 
detects violations and displays findings in the form of a report, but puts us in 
control of remediation.

[Cloud Build](https://cloud.google.com/cloud-build/docs/) is a service that 
executes your builds on Google Cloud Platform infrastructure. Cloud Build can 
import source code from Google Cloud Storage, Cloud Source Repositories, GitHub, 
or Bitbucket, execute a build to your specifications, and produce artifacts such 
as Docker containers or Java archives. 

---

Integration tests are hosted in the [forseti-security repository](https://github.com/forseti-security/forseti-security/tree/master/integration_tests/tests/forseti). 
InSpec framework is used to write integration tests.

## **Adding an integration test**

- Integration tests are enclosed in a `describe` block. Multiple `describe`
blocks are usually grouped together in a `control`. [Determine if a control 
already exists](https://github.com/forseti-security/forseti-security/tree/master/integration_tests/tests/forseti/controls) 
for the module associated with your Forseti contributions.
- If a control already exists, InSpec test for your Forseti contributions should 
be added in the same `control`.
- If a new control needs to be added, create a ruby file and add the `control`
in that file. Update the `controls` section in [.kitchen.yml](https://github.com/forseti-security/forseti-security/blob/master/.kitchen.yml) 
with the newly created `control`.
- GCP resources required to test a particular scenario can be created using [Terraform](https://www.terraform.io/docs/providers/google/index.html)
or using `gcloud` commands within the InSpec test. InSpec tests run on server VM 
and almost everything that can be done using Linux commands can be accomplished 
in the scope of a test.
- Creation of new resources may require updating [main.tf](https://github.com/forseti-security/forseti-security/blob/master/integration_tests/fixtures/forseti/main.tf), 
[variables.tf](https://github.com/forseti-security/forseti-security/blob/master/integration_tests/fixtures/forseti/variables.tf), 
[outputs.tf](https://github.com/forseti-security/forseti-security/blob/master/integration_tests/fixtures/forseti/outputs.tf) 
and [inspec.yml](https://github.com/forseti-security/forseti-security/blob/master/integration_tests/tests/forseti/inspec.yml).
- Commands executed to set the ground should be placed in the `before` block.
- In the `describe` block, you can also test for a command that should/should not
exist. 
- You can also make assertions against standard output (stdout), standard 
error (stderr), exist status code (exit_status) to name a few.
- Commands that are executed for clean-up purposes such as deleting inventory
and model should be placed in the `after` block. 

## **What's next**

* Learn the [basic syntax to add an integration test using the InSpec framework](https://www.inspec.io/docs/reference/glossary/).
* Learn how to [run the test suite]({% link _docs/latest/develop/test/integration-testing/run-test-suite.md %}).
