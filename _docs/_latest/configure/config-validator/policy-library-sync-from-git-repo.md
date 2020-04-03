---
title: Policy Library Sync from Git Repository
order: 702
---

# {{ page.title }}

This page describes how to sync policies from Git repository.

---

## **Policy Library Sync from Git Repository**

As part of the Terraform configuration, you will need to include a few 
additional variables to enable the git-sync feature.

Before configuring the config file, we recommend you to set up the Policy 
Library repository by following the steps listed [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#how-to-set-up-constraints-with-policy-library) .

In your `main.tf` file, set the `policy_library_sync_enabled` variable in the 
Forseti Terraform module to `"true"` to enable git-sync, and set the 
`policy_library_repository_url` to the URL for your Policy Library repository; 
git protocol is recommended.

You can set the `policy_library_repository_branch` to the specific git branch
containing the policies. By default, policies from the `master` branch are synced.

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "PROJECT_ID"
  org_id                   = "ORG_ID"
  domain                   = "DOMAIN"
  
  ...
  
  config_validator_enabled          = "true"
  policy_library_sync_enabled       = "true"
  policy_library_repository_url     = "git@github.com:forseti-security/policy-library"
}
```

(OPTIONAL) `policy_library_sync_ssh_known_hosts`: Provide the [known host keys](https://www.ssh.com/ssh/host-key)
for the git repository. This can be obtained by running ssh-keyscan 
${YOUR_GIT_HOST}.

You should also setup an outputs.tf configuration file for Terraform to obtain the auto-generated public SSH key.

``` 
output "forseti-server-git-public-key-openssh" {
  description = "The public OpenSSH key generated to allow the Forseti Server to clone the policy library repository."
  value       = module.forseti.forseti-server-git-public-key-openssh
}
```

**IMPORTANT:** After applying the Terraform configuration, you will need to add 
the generated SSH key to the git user account. The SSH key will be provided as 
an output from Terraform. If the Policy Library repository is hosted on GitHub, 
you can [follow these steps to add the SSH key to your account](https://help.github.com/en/github/authenticating-to-github/adding-a-new-ssh-key-to-your-github-account).

To obtain the generated SSH key from Terraform run this command:

```
terraform output forseti-server-git-public-key-openssh
```

You can view any logs related to this process from Stackdriver Logging by 
searching for `git-sync`.

**Note:**
- The Config Validator service need to be restarted after policies are synced 
over. This is done automatically by the cron job that runs every 2 hours by 
default. However, if you are running ad-hoc scans, you can restart the Config
Validator service to pick up the latest policies by running `sudo systemctl 
restart config-validator`. You can check the status of the service by running
`sudo systemctl status config-validator`.

## **What’s next**
* Learn about end-to-end workflow with sample constraint [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#end-to-end-workflow-with-sample-constraint).
* Learn about how to write your own constraints using pre-defined constraint
template [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#how-to-set-up-constraints-with-policy-library).
