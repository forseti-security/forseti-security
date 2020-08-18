---
title: Policy Library Sync From GCS
order: 701
---

# {{ page.title }}

This page describes how to sync policies from GCS to the Forseti Server. This feature is supported with Forseti on GCE 
and Forseti on GKE.

---

## **Policy Library Sync From GCS**

The default behavior of Forseti is to sync the Policy Library from the Forseti Server GCS bucket. As part of the cron 
job that collects an inventory and performs a scan, the policies will be copied down before each scan.

To sync policies from GCS to the Forseti server, you will need to create the GCS folder.

Open the Forseti project in the [Google Cloud Console](https://console.cloud.google.com/) and go to **Storage** in the 
menu. The Forseti Server bucket will be named `forseti-server-{SUFFIX}` where `{SUFFIX}` is a random 8 character suffix 
created at the time Forseti is deployed. Create a folder with the name `policy-library` inside the Forseti Server 
bucket and make note of the suffix.

Assuming you have a local copy of your policy library repository, you can follow these steps to copy them to GCS 
(replace `{SUFFIX}` with the suffix noted above):

```
export FORSETI_BUCKET=forseti-server-{SUFFIX}
export POLICY_LIBRARY_PATH=path/to/local/policy-library
gsutil -m rsync -d -r ${POLICY_LIBRARY_PATH}/policies gs://${FORSETI_BUCKET}/policy-library/policies
gsutil -m rsync -d -r ${POLICY_LIBRARY_PATH}/lib gs://${FORSETI_BUCKET}/policy-library/lib
```

After this is done, Forseti will pick up the new policies in the next scanner run.

## **Ad-hoc Scanning**

If you would like to run an ad-hoc scan by connecting to the Forseti VMs via SSH, you can copy the policies from GCS and
will need to restart the Config Validator service. **Note**: While a scan can be done from either of the VMs, you will
need to SSH to copy the policies and restart Config Validator.

```
sudo mkdir -m 777 -p "$POLICY_LIBRARY_HOME/policy-library"
sudo gsutil -m rsync -d -r "gs://$SCANNER_BUCKET/policy-library" "$POLICY_LIBRARY_HOME/policy-library"
sudo systemctl restart config-validator
```

## **What’s next**
* Learn about the end-to-end workflow to apply a sample constraint [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#end-to-end-workflow-with-sample-constraint).
* Learn how to customize a constraint [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#instantiate-constraints).
