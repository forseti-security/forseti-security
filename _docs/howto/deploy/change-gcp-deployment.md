---
title: Updating a GCP Deployment
order: 104
---
#  {{ page.title }}

### Get a particular deployment template version
**This step is optional**.

If you need to change the `release-version` for your Forseti deployment, you MUST 
get the correct version of Forseti. The deployment template's startup 
script has release-specific code, so things will break if you use a startup script that 
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
   
   "I want to deploy Release 1.1.3:":
   
   ```yaml
   # branch-name: ...
   release-version: "1.1.3"
   ```

### Change deployment properties
1. Check `deploy-forseti.yaml.sample` to see if there are any new properties 
   that you need to copy over to your previous `deploy-forseti.yaml`. You can use
   `git diff` to compare what changed. For example, to see the diff between the latest 
   (HEAD) and one revision ago:

   ```bash
   $ git diff origin..HEAD~1 -- deploy-forseti.yaml.sample
   ```

1. Edit `deploy-forseti.yaml` and update the values you want to change. If you 
   previously deployed the `master` branch, you don't need to change it.
   
### Run the Deployment Manager update
Run the following update command:

```bash
$ gcloud deployment-manager deployments update DEPLOYMENT_NAME \
  --config path/to/deploy-forseti.yaml
```

If you changed the properties in the `deploy-forseti.yaml` "Compute Engine" 
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
