# Timesketch deployment

Timesketch is an open source collaborative forensic timeline analysis tool. It uses full text search to give you insight into your timelines. You can search hundreds of millions of events across different timelines all at once. Share your findings using saved views and add meaning to your data with labels and comments. Bring life to your investigation with Timesketch Stories. Timesketch is build around collaboration, sharing and search.

## Installing Terraform

Please follow [these
instructions](https://www.terraform.io/intro/getting-started/install.html) to
install Terraform binary on your machine.

## Setting up a Google Cloud Project

1.  Create a new project in GCP console
    ([link](https://console.cloud.google.com/project)). Let's assume it's called
    "timesketch-deployment-test".
1.  Enable billing for the project
    ([link](https://support.google.com/cloud/answer/6293499#enable-billing)).

## Running Terraform

`cd` to the folder with Terraform configuration files (and where this README
file is).

If it's the first time you run Terraform with this set of configuration files,
run:

```bash
terraform init
```

Then run (`timesketch-deployment-test` is the name of a project that you've previously
set up):

```bash
terraform apply -var 'gce_project=timesketch-deployment-test'
```

Run the following to get the URL of a newly deployed Timesketch server:

```bash
terraform output
```
