**Note**: This is an early (alpha) release and the deployment is not fully polished yet. You are welcome to test it out and if you have any questions on how to use the tools please reach out to the official mailing lists.

**Note**: This setup will add billing costs to your project.

## Installing Terraform

Please follow [these
instructions](https://www.terraform.io/intro/getting-started/install.html) to
install Terraform binary on your machine.

## Setting up a Google Cloud Project

1.  Create a new project in GCP console
    ([link](https://console.cloud.google.com/project)). Let's assume it's called
    "gcp-forensics-deployment-test".
1.  Enable billing for the project
    ([link](https://support.google.com/cloud/answer/6293499#enable-billing)).

## Instrumenting Terraform with credentials

1.  In Cloud Platform Console, navigate to the [Create service account
    key](https://console.cloud.google.com/apis/credentials/serviceaccountkey)
    page.
1.  From the Service account dropdown, select Compute Engine default service
    account, and leave JSON selected as the key type.
1.  Click Create, which downloads your credentials as a file named
    `[PROJECT_ID]-[UNIQUE_ID].json`.
1.  In the same shell where you're going to run Terraform (see below), run the
    following:

```bash
export GCLOUD_KEYFILE_JSON=/absolute/path/to/downloaded-file.json
```

## Running Terraform

`cd` to the folder with Terraform configuration files (and where this README
file is).

If it's the first time you run Terraform with this set of configuration files,
run:

```bash
terraform init
```

Then run (`gcp-forensics-deployment-test` is the name of a project that you've previously
set up):

```bash
terraform apply -var 'gcp_project=gcp-forensics-deployment-test'
```

Run the following to get information about the newly deployed infrastructure:

```bash
terraform output
```
