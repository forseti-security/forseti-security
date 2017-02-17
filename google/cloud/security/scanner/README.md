# Scanner

The Forseti policy scanner takes in a rules definition file (either json or
yaml) and uses it to audit your Google Cloud Platform resources (e.g.
organizations, projects). After running the audit, it outputs a csv file and
optionally writes it to a bucket in Google Cloud Storage.

## Running the scanner

* Before running the scanner, make sure you've installed the forseti-security
  package. See the [README](/README.md) in the top-level directory of this repo.

* Create a new project and setup billing.

* Update gcloud (the following gcloud commands have been tested with version
  1.3.8):

```sh
$ gcloud components update
```

* Set your gcloud environment to use this project. To create a new environment
  configuration:

```sh
$ gcloud init
```

* Add the `PROJECTID-compute@developer.gserviceaccount.com` service account from
  your project IAM onto your organization IAM settings. Grant it the `Browser`
  role.

* Authenticate your application-default credentials:

```sh
$ gcloud auth application-default login
```

* A sample rules file can be found in the samples/ directory. You should edit
  this to fit your environment.

* To see all the available commandline flags for the scanner, run:

```sh
$ cloud_scanner --helpfull
```

If `cloud_scanner` is not found, you probably need to activate the virtualenv of
your Forseti installation.

To run the scanner with a local rules file:

```sh
$ cloud_scanner --rules path/to/rules.yaml
```

To run the scanner with a rules file stored in GCS, e.g.
`gs://my-project-id/rules/rules.yaml`:

```sh
$ cloud_scanner --rules "rules/rules.yaml" --input_bucket my-project-id
```

To specify the output location for the violations:

```sh
$ cloud_scanner --rules "rules/rules.yaml" --output_path path/for/output/
```

* By default, the scanner will save the csv output to `/tmp`. Specify an output bucket
in order to save the csv there.


## Defining rules

### Schema

TBD

```yaml
```
