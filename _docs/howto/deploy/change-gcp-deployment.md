---
title: Updating a GCP Deployment
order: 104
---
#  {{ page.title }}

This page describes how to change or _upgrade_ an existing installation of Forseti.

There are four steps steps to upgrading existing deployments of Forseti.

 1. [Upgrade the codebase](#get-the-latest-version)
 1. [Check for differences in the deployment](#check-for-changes-to-the-deployment-template)
 1. [Check for and enable any new capabilities](#enable-new-features)
 1. [Upgrade the deployment](#update-the-deployment)

## Get the latest version

This step is **optional** if you're not changing versions of Forseti.

If you need to change the `release-version` for your Forseti deployment, you **MUST** 
get the correct version of Forseti. The deployment template's startup 
script has release-specific code, so things will break if you use a startup script that 
is out of sync with the deployed release.

Note: If you used the Forseti setup wizard to deploy your `deploy-forseti.yaml` 
will have a timestamp suffix, e.g. `deploy-forseti-20171001000000.yaml`.

1. Sync master branch:

   ```bash
   $ git checkout master
   $ git pull
   ```

2. Checkout the version you want to deploy. (It is NOT recommended to get a previous 
   version.) If you want the latest release, you don't have to do this step; `master` 
   points to the latest release.
   
   If you want to get a specific release, e.g. Release 1.1.3:
   
   ```bash
   $ git checkout v1.1.3
   ```

3. You will use this release version in your `deploy-forseti.yaml` file as follows:

   "I want to deploy `master` branch":
   
   ```yaml
   branch-name: "master"
   # release-version: ...
   ```
   
   "I want to deploy Release 1.1.3":
   
   ```yaml
   # branch-name: ...
   release-version: "1.1.3"
   ```

## Check for changes to the deployment template

1. Check `deploy-forseti.yaml.sample` to see if there are any new properties 
   that you need to copy over to your previously generated 
   `deploy-forseti-<TIMESTAMP>.yaml`. You can use `git diff` to compare what 
   changed. For example, to see the diff between the latest (HEAD) and one revision ago:

   ```bash
   $ git diff origin/master..HEAD~1 -- deploy-forseti.yaml.sample
   ```

1. Edit `deploy-forseti-<TIMESTAMP>.yaml` and update the values of the new properties.

For example, from v1.1.7 to v1.1.10, the following Compute Engine instance 
properties have been changed and/or added.

   ```yaml
   region: $(ref.cloudsql-instance.region)

   network-host-project-id: NETWORK_HOST_PROJECT_ID
   vpc-name: VPC_NAME
   subnetwork-name: SUBNETWORK_NAME
   ```

To upgrade, copy these new properties to your generated 
deploy-forseti-<TIMESTAMP>.yaml. Then, update the placeholders to the values 
you want to use. For example, the id of the project that Forseti is 
running in, "default", "default".

1. Inspect `deploy-forseti-<TIMESTAMP>.yaml` and verify if your ```branch-name``` 
   property is hardcoded to a specific version. If so, update it to the latest 
   version.
   
## Finally update the Deployment

Run the following update command:

```bash
$ gcloud deployment-manager deployments update DEPLOYMENT_NAME \
  --config path/to/deploy-forseti-<TIMESTAMP>.yaml
```

If you changed the properties in the `deploy-forseti-<TIMESTAMP>.yaml` "Compute Engine" 
section or the startup script in `forseti-instance.py`, you need to reset 
the instance for changes to take effect:

  ```bash
  $ gcloud compute instances reset COMPUTE_ENGINE_INSTANCE_NAME
  ```

The Compute Engine instance will restart and perform a fresh installation of Forseti, so you do 
not need to ssh to the instance to run all the git clone/python install commands.

Some resources can't be updated in a deployment. If you see an error that you can't 
change a certain resource, you'll need to create a new deployment of Forseti.

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).
is out of sync with the deployed release.

1. Sync master branch:

   ```bash
   $ git checkout master
   $ git pull
   ```

2. Checkout the version you want to deploy. (It is NOT recommended to get a previous 
   version.) If you want the latest release, you don't have to do this step; `master` 
   points to the latest release.
   
   If you want to get a specific release, e.g. Release 1.1.3:
   
   ```bash
   $ git checkout v1.1.3
   ```

3. You will use this release version in your `deploy-forseti.yaml` file as follows:

   "I want to deploy `master` branch":
   
   ```yaml
   branch-name: "master"
   # release-version: ...
   ```
   
   "I want to deploy Release 1.1.3":
   
   ```yaml
   # branch-name: ...
   release-version: "1.1.3"
   ```

## Change deployment properties

1. Check `deploy-forseti.yaml.sample` to see if there are any new properties 
   that you need to copy over to your previously generated 
   `deploy-forseti-<TIMESTAMP>.yaml`. You can use `git diff` to compare what 
   changed. For example, to see the diff between the latest (HEAD) and one revision ago:

   ```bash
   $ git diff origin/master..HEAD~1 -- deploy-forseti.yaml.sample
   ```

1. Edit `deploy-forseti-<TIMESTAMP>.yaml` and update the values of the new properties.

For example, from v1.1.7 to v1.1.10, the following Compute Engine instance 
properties have been changed and/or added.

   ```yaml
   region: $(ref.cloudsql-instance.region)

   network-host-project-id: NETWORK_HOST_PROJECT_ID
   vpc-name: VPC_NAME
   subnetwork-name: SUBNETWORK_NAME
   ```

To upgrade, copy these new properties to your generated 
deploy-forseti-<TIMESTAMP>.yaml. Then, update the placeholders to the values 
you want to use. For example, the id of the project that Forseti is 
running in, "default", "default".

1. Inspect `deploy-forseti-<TIMESTAMP>.yaml` and verify if your ```branch-name``` 
   property is hardcoded to a specific version. If so, update it to the latest 
   version.

## Enable new features

To enable any new capabilites in the release you might need to update the configuration Forseti
uses. For instance you might want to enable the inventorying of a new resource and the scanner rules
necessary to audit it.

To do this its best to:

  1. Review the release notes for version of Forseti you used from above.
  1. Review the configuration Forseti uses (this is likely stored in GCS) and compare it to the
    sample for that release (`configs/forseti_conf.yaml.sample`) to see what's new.
  1. Review the list of [scanners]({% link _docs/quickstarts/scanner/rules.md %}) and their rules to
    then adjust your rules accordingly (these are 
    likely stored in GCS) .
    
## Update the deployment

Run the following update command:

```bash
$ gcloud deployment-manager deployments update DEPLOYMENT_NAME \
  --config path/to/deploy-forseti-<TIMESTAMP>.yaml
```

If you changed the properties in the `deploy-forseti-<TIMESTAMP>.yaml` "Compute Engine" 
section or the startup script in `forseti-instance.py`, you need to reset 
the instance for changes to take effect:

  ```bash
  $ gcloud compute instances reset COMPUTE_ENGINE_INSTANCE_NAME
  ```

The Compute Engine instance will restart and perform a fresh installation of Forseti, so you do 
not need to ssh to the instance to run all the git clone/python install commands.

Some resources can't be updated in a deployment. If you see an error that you can't 
change a certain resource, you'll need to create a new deployment of Forseti.

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).

