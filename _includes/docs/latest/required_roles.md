**Granted at the Organization level**

 `forseti_inventory` and `forseti_scanner` require:
 
 * `roles/bigquery.dataViewer`
 * `roles/browser`
 * `roles/compute.networkViewer`
 * `roles/iam.securityReviewer`
 * `roles/appengine.appViewer`
 * `roles/servicemanagement.quotaViewer`
 * `roles/cloudsql.viewer`
 
 `forseti_enforcer` requires:
 
 * `roles/compute.securityAdmin`

**Granted on the project where Forseti Security is deployed**

 `forseti_inventory`, `forseti_scanner`, and `forseti_enforcer` require:

 * `roles/storage.objectViewer`
 * `roles/storage.objectCreator`
 * `roles/logging.logWriter`
 
 `forseti_inventory`, `forseti_scanner`, and `forseti_iam` require:
 
 * `roles/cloudsql.client`
