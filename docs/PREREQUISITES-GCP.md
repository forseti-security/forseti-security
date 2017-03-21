# Prerequisites to installing on GCP
* [Installing gcloud](installing-gcloud)
* [Create a GCP project with associated billing](#create-a-gcp-project-with-associated-billing)
* [Enable required APIs](#enable-required-apis)
* [Set up a service account](#set-up-a-service-account)

## Installing gcloud
[Download and install](https://cloud.google.com/sdk/gcloud/) `gcloud`. Verify whether the output of `gcloud info` shows the right project and account. If not, login and init your environment (see following steps).

  ```sh
  $ gcloud components update
  ```

  ```sh
  $ gcloud info

    ... some info ...

  Account: [user@company.com]
  Project: [my-forseti-security-project]

  Current Properties:
    [core]
      project: [my-forseti-security-project]
      account: [user@company.com]

    ... more info ...
  ```

## Enable required APIs
* Initialize your `gcloud` commandline environment to select your project and auth your Google Cloud account.

  ```sh
  $ gcloud init
  ```

* Enable **Cloud SQL API**.

  ```sh
  $ gcloud beta service-management enable sql-component.googleapis.com
  ```

* Enable **Cloud SQL Admin API**.

  ```sh
  $ gcloud beta service-management enable sqladmin.googleapis.com
  ```

* Enable **Deployment Manager API**.

  ```sh
  $ gcloud beta service-management enable deploymentmanager.googleapis.com
  ```
