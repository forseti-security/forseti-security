---
title: Changing a Deployment
order: 104
---
#  {{ page.title }}

This page describes how to change a Forseti Security deployment. Most changes
to a deployment are usually to the deployment properties, such as the
instance type or `src-path` when you want your deployment to run a certain 
version of Forseti Security. To update your deployment, follow the process below:

  1. Edit `deploy-forseti.yaml` and update the values you want to change.
  1. Run the following update command:

      ```bash
      $ gcloud deployment-manager deployments update DEPLOYMENT_NAME \
       --config path/to/deploy-forseti.yaml
      ```

If you change the properties in the `deploy-forseti.yaml` "Compute Engine" 
section or the startup script in `forseti-instance.py`, you need to reset 
the instance for changes to take effect:

  ```bash
  $ gcloud compute instances reset COMPUTE_ENGINE_INSTANCE_NAME
  ```

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).
