---
title: Policy Library Sync from Git Repository
order: 702
---

# {{ page.title }}

This page describes how to sync Config Validator policies to the Forseti server from a Git repository. This feature 
uses the [git-sync image](https://github.com/kubernetes/git-sync) to sync any changes in a Git repository to the Forseti
server VM. This feature is supported with Forseti on GCE and Forseti on GKE.

---

## **Policy Library Sync from Git Repository**

As part of the Terraform configuration, you will need to include a few additional variables to enable the git-sync 
feature.

First you will need to set up the Policy Library repository by following the steps listed 
[here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#how-to-set-up-constraints-with-policy-library).

In the Forseti Terrraform `main.tf` file, set the `policy_library_sync_enabled` variable in the Forseti Terraform 
module to `true` to enable git-sync, and set the `policy_library_repository_url` to the URL for your Policy Library 
repository; the Git protocol is recommended.

You can set the `policy_library_repository_branch` to the specific git branch containing the policies. By default, 
policies from the `master` branch are synced.

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "PROJECT_ID"
  org_id                   = "ORG_ID"
  domain                   = "DOMAIN"
  
  ...
  
  config_validator_enabled      = true
  policy_library_sync_enabled   = true
  policy_library_repository_url = "git@github.com:forseti-security/policy-library"
}
```

(OPTIONAL) `policy_library_sync_ssh_known_hosts`: Provide the [known host keys](https://www.ssh.com/ssh/host-key)
for the git repository. This can be obtained by running ssh-keyscan ${YOUR_GIT_HOST}.

### **Important Note**

In order to connect to the private Policy Library repository, Terraform will generate an SSH key that will need to be 
added to the Git user account. Once the SSH key has been added, then the git-sync container will be able to clone the 
repository on the Forseti server VM. [Follow these steps to add the SSH key to your account](https://help.github.com/en/github/authenticating-to-github/adding-a-new-ssh-key-to-your-github-account).

You can set up a Terraform outputs.tf file for to obtain the auto-generated public SSH key. Example output for the SSH 
key.

``` 
output "forseti-server-git-public-key-openssh" {
  description = "The public OpenSSH key generated to allow the Forseti Server to clone the policy library repository."
  value       = module.forseti.forseti-server-git-public-key-openssh
}
```

To obtain the generated SSH key from Terraform run this command:

```
terraform output forseti-server-git-public-key-openssh
```

## **Logs and Troubleshooting**

- Git-sync logs can be found in the Forseti server VM [Cloud logs](https://cloud.google.com/logging).
- All git-sync logs are logged to the `gcplogs-docker-driver` log with no log level, along with the Config Validator 
logs.
- To only view the git-sync logs, select the `gcplogs-docker-driver` log and search for `git-sync`.
- You can check that the git-sync service is actively running with the following command in the Forseti server 
VM:

```bash
  sudo systemctl status policy-library-sync
```

## **Ad-hoc Scanning**

After commiting changes to your private Git repository, you can run an ad-hoc scan by connecting to the Forseti server. 
Those changes will be automatically synced to the Forseti server within 30 seconds. You can then SSH to the Forseti
server and run a scan, however you will need to restart the Config Validator service. This step is automated as part of 
the cron job. Run the following command to restart Config Validator:

```
sudo systemctl restart config-validator
```

## **What’s next**
* Learn about the end-to-end workflow to apply a sample constraint [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#end-to-end-workflow-with-sample-constraint).
* Learn how to customize a constraint [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#instantiate-constraints).
