
Forseti supports the scanning GCP projects for granted users that might be a GSuite Google group. Doing this requires taking special steps on the previously created service account and within the GSuite domain.

To do this you must enable Domain-wide Delegation "DWD" ([details](https://cloud.google.com/appengine/docs/flexible/python/authorizing-apps#google_apps_domain-wide_delegation_of_authority)) for the previously created service account.


* Enable the **Admin SDK API**

  ```sh
  $ gcloud beta service-management list enable admin.googleapis.com
  ```
