---
title: Updating Forseti
order: 104
---
#  {{ page.title }}

### Update local installation
If you want to update your local version of Forseti, pull in the latest changes from
git:

```bash
$ cd forseti-security
$ git pull
```

And then run the python installation:

```bash
$ python setup.py install
```

### Change deployment properties
If you need to change any of the properties for your Forseti deployment, such as the
`release-version`, follow the process below:

  1. If you **do not** need to update your Forseti version, continue on to step 3.
     Sync your local git code (where you ran Deployment Manager) so you get the latest 
     deployment templates. This is important because a newer version of Forseti might 
     also require an updated startup script on the GCE instance.
     
     To get the latest version of Forseti, sync your master branch:
     
     ```bash
     $ git checkout master
     $ git pull
     ```
     
  1. Check `deploy-forseti.yaml.sample` to see if there are any new properties 
     that you need to copy over to your previous `deploy-forseti.yaml`.
  1. Edit `deploy-forseti.yaml` and update the values you want to change. If you 
     previously deployed the `master` branch, you don't need to change it.
  1. Run the following update command:

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

The GCE instance will restart and perform a fresh installation of Forseti, so you do 
not need to ssh to the instance to run all the git clone/python install commands.

There are limitations as to what resources you can update in your deployment. If you 
see an error that you cannot change a certain resources, it's likely that you will need 
to create a new deployment instead.

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).
