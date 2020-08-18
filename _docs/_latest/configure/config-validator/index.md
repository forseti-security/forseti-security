---
title: Config Validator
order: 700
---

# {{ page.title }}

This page lists the steps to configure Config Validator with the Forseti Terraform module. Config Validator is 
supported with Forseti on GCE and Forseti on GKE.

---

## **Enable the Config Validator Scanner**

In your `main.tf` file, set the `config_validator_enabled` variable in the Forseti Terraform module to `true`:

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "PROJECT_ID"
  org_id                   = "ORG_ID"
  domain                   = "DOMAIN"
  
  ...
  
  config_validator_enabled = true
```

### **Additional Config Validator variables**

There are some additional Config Validator variables that can be set within the Terraform configuration:

- `config_validator_image`: The path to the Config Validator image. **The default value is strongly recommended.**
- `config_validator_image_tag`: The tag or version of the Config Validator image. **The default value is strongly 
recommended.**
- `config_validator_violations_should_notify`: Include Config Validator violations for any notifiers; this is enabled by
default.

## **Policy Library**

Before deploying Forseti, the Policy Library will need to be set up so that Config Validator knows what to scan. The 
Forseti Policy Library offers a great list of [sample constraints](https://github.com/forseti-security/policy-library/tree/master/samples) 
that you can use to get started.

You can provide policies to the Forseti Server in two ways:
- [Sync policies from GCS (default behavior)]({% link _docs/latest/configure/config-validator/policy-library-sync-from-gcs.md %})
- [Sync policies from a Git repository]({% link _docs/latest/configure/config-validator/policy-library-sync-from-git-repo.md %})

## **Deploy Forseti with Config Validator**

Once you have configured the Forseti Terraform module and set up a Policy Library, then deploy Forseti with Terraform.

```
terraform apply
```

## **Logs and Troubleshooting**

- Config Validator logs can be found in the Forseti server VM [Cloud logs](https://cloud.google.com/logging).
- All Config Validator logs are logged to the `gcplogs-docker-driver` log with no log level.
- To only view the Config Validator logs, select the `gcplogs-docker-driver` log and search for `config-validator`; 
there are some other processes that log to the log as well, such as the git-sync process.
- You can check that the config-validator service is actively running with the following command in the Forseti server 
VM:

```bash
  sudo systemctl status config-validator
```

## Support

Please reach out to the [Forseti Security Team]({% link _docs/latest/use/get-help.md %}) for support.
