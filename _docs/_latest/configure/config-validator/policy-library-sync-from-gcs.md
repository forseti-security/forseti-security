---
title: Policy Library Sync From GCS
order: 701
---

# {{ page.title }}

This page describes how to sync policies from the GCS to the Forseti Server.

---

## **Policy Library Sync From GCS**

The default behavior of Forseti is to sync the Policy Library from the Forseti 
Server GCS bucket. 

To sync policies from GCS to the Forseti server, you will need to create the GCS folder.

Open the Forseti project in the [Google Cloud Console](https://pantheon.corp.google.com/)
and go to Storage in the menu. The Forseti Server bucket will be named 
`forseti-server-{SUFFIX}` where `{SUFFIX}` is a random 8 character suffix setup 
at the time Forseti is deployed. Create a folder with the name `policy-library` 
inside the Forseti Server bucket and make note of the suffix.

Assuming you have a local copy of your policy library repository, you can follow 
these steps to copy them to GCS (replace `{SUFFIX}` with the suffix noted above):

```
export FORSETI_BUCKET=forseti-server-{SUFFIX}
export POLICY_LIBRARY_PATH=path/to/local/policy-library
gsutil -m rsync -d -r ${POLICY_LIBRARY_PATH}/policies gs://${FORSETI_BUCKET}/policy-library/policies
gsutil -m rsync -d -r ${POLICY_LIBRARY_PATH}/lib gs://${FORSETI_BUCKET}/policy-library/lib
```
After this is done, Forseti will pick up the new policy library content in the 
next scanner run.

## **What’s next**
* Learn about end-to-end workflow with sample constraint [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#end-to-end-workflow-with-sample-constraint).
* Learn about how to write your own constraints using pre-defined constraint
template [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#how-to-set-up-constraints-with-policy-library).
