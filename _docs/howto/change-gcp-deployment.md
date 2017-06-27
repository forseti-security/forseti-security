---
title: Changing a Deployment
order: 2 
---
#  {{ page.title }}

This page describes how to change a Forseti Security deployment. Most changes
to a deployment are usually to the deployment properties, such as the
notification email address, instance type, or `src-path` when you want your deployment to run a certain version of Forseti Security. To update your deployment, follow the process below:

  1. Edit `deploy-forseti.yaml` and update the values you want to change.
  1. Run the following update command:

      ```bash
      $ gcloud deployment-manager deployments update forseti-security \
       --config path/to/deploy-forseti.yaml
      ```

If you change the Compute Engine instance's startup script, such as changing
the properties in the `deploy-forseti.yaml` "Compute Engine" section or the
startup script in `forseti-instance.py`, you may need to reset the instance.
To reset the instance and make sure changes take effect, run the following
command:

```bash
$ gcloud compute instances reset COMPUTE_ENGINE_INSTANCE_NAME
```

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).
