---
title: Config Validator
order: 700
---

# {{ page.title }}

This page lists the steps to set up Config Validator Scanner. 

---

## **Setting up Config Validator Scanner**

In your `main.tf` file, set the `config_validator_enabled` variable in the 
Forseti Terraform module to `"true"`:

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "PROJECT_ID"
  org_id                   = "ORG_ID"
  domain                   = "DOMAIN"
  
  ...
  
  config_validator_enabled   = "true"
  config_validator_image     = "CONFIG_VALIDATOR_IMAGE"
  config_validator_image_tag = "CONFIG_VALIDATOR_IMAGE_TAG"
}
```

**Note:**
- You will be notified when Config Validator violations are found as 
`config_validator_violations_should_notify` is set to `"true"` by default.
- `config_validator_image` and `config_validator_image_tag` should be set 
only when you want to use a specific Config Validator image or tag. Default 
values can be found [here](https://github.com/forseti-security/terraform-google-forseti#inputs).
Versions of Config Validator newer than the default value included use OPA 
0.17.x, which is not compatible with some of the policies. Please reach out to 
the [Forseti Security Team](https://forsetisecurity.org/docs/latest/use/get-help.html) 
to see if the specific Config Validator image/tag that you want to you use is 
supported.


Apply the Terraform module.

```
terraform apply
```

At this point, you are ready to add your own constraints in your policy-library 
and start scanning your infrastructure for violations based on them. The Forseti 
project offers a great list of [sample constraints](https://github.com/forseti-security/policy-library/tree/master/samples) 
you can use freely to get started.

You can provide policies to the Forseti Server in two ways:
- Sync policies from GCS to the Forseti Server (default behavior)
- Enable the git sync feature to allow Forseti to automatically sync policy 
updates to your Forseti Server to be used by future scans. 

## **Troubleshooting**

- You can find out what errors have happened by viewing any logs related to this 
process from Operations Logging by searching for `config-validator`.
- Operations Logging displays `All Logs` from the Forseti Server VM by default. 
Change the log filter by selecting `forseti` from the drop-down menu to 
view Forseti logs. Similarly, select `gcplogs-docker-driver` to view the
docker logs for `config-validator` and `git-sync` services.   
- You can also check that the config-validator service is running and healthy by 
running the following command in the Forseti server VM:

```bash
  sudo systemctl status config-validator
```

## **What’s next**
* Learn about syncing policies from GCS to the Forseti Server [here]({% link _docs/latest/configure/config-validator/policy-library-sync-from-gcs.md %}).
* Learn about enabling the git sync feature to provide policies to the Forseti 
Server [here]({% link _docs/latest/configure/config-validator/policy-library-sync-from-git-repo.md %}).
