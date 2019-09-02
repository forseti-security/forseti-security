/**
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#----------------#
# Forseti config #
#----------------#
variable "project_id" {
  description = "Google Project ID that you want Forseti deployed into"
}

variable "gsuite_admin_email" {
  description = "G-Suite administrator email address to manage your Forseti installation"
  default = ""
}

variable "forseti_version" {
  description = "The version of Forseti to install"
  default     = "v2.17.0"
}

variable "forseti_repo_url" {
  description = "Git repo for the Forseti installation"
  default     = "https://github.com/GoogleCloudPlatform/forseti-security"
}

variable "forseti_email_recipient" {
  description = "Email address that receives Forseti notifications"
  default     = ""
}

variable "forseti_email_sender" {
  description = "Email address that sends the Forseti notifications"
  default     = ""
}

variable "forseti_home" {
  description = "Forseti installation directory"
  default     = "$USER_HOME/forseti-security"
}

variable "forseti_run_frequency" {
  description = "Schedule of running the Forseti scans"
  default     = "0 */2 * * *"
}

#----------------#
# Forseti server #
#----------------#
variable "server_type" {
  description = "GCE Forseti Server role instance size"
  default     = "n1-standard-2"
}

variable "server_region" {
  description = "GCP region where Forseti will be deployed"
  default     = "us-central1"
}

variable "server_boot_image" {
  description = "GCE instance image that is being used, currently Ubuntu only support is available"
  default     = "ubuntu-os-cloud/ubuntu-1804-lts"
}

variable "server_instance_metadata" {
  description = "Metadata key/value pairs to make available from within the server instance."
  type        = "map"
  default     = {}
}

variable "server_grpc_allow_ranges" {
  description = "List of CIDRs that will be allowed gRPC access to forseti server"
  type        = "list"
  default     = ["10.128.0.0/9"]
}

variable "server_ssh_allow_ranges" {
  description = "List of CIDRs that will be allowed ssh access to forseti server"
  type        = "list"
  default     = ["0.0.0.0/0"]
}

variable "server_tags" {
  description = "GCE Forseti Server VM Tags"
  type        = "list"
  default     = []
}

variable "server_access_config" {
  description = "Server instance 'access_config' block"
  type        = "map"
  default     = {}
}

variable "server_private" {
  description = "Private GCE Forseti Server VM (no public IP)"
  default     = "false"
}

#---------------------------------#
# Forseti server config inventory #
#---------------------------------#
variable "admin_max_calls" {
  description = "Maximum calls that can be made to Admin API"
  default     = "14"
}

variable "admin_period" {
  description = "The period of max calls for the Admin API (in seconds)"
  default     = "1.0"
}

variable "admin_disable_polling" {
  description = "Whether to disable polling for Admin API"
  default     = "False"
}

variable "appengine_max_calls" {
  description = "Maximum calls that can be made to App Engine API"
  default     = "18"
}

variable "appengine_period" {
  description = "The period of max calls for the App Engine API (in seconds)"
  default     = "1.0"
}

variable "appengine_disable_polling" {
  description = "Whether to disable polling for App Engine API"
  default     = "False"
}

variable "bigquery_max_calls" {
  description = "Maximum calls that can be made to Big Query API"
  default     = "160"
}

variable "bigquery_period" {
  description = "The period of max calls for the Big Query API (in seconds)"
  default     = "1.0"
}

variable "bigquery_disable_polling" {
  description = "Whether to disable polling for Big Query API"
  default     = "False"
}

variable "cloudasset_max_calls" {
  description = "Maximum calls that can be made to Cloud Asset API"
  default     = "1"
}

variable "cloudasset_period" {
  description = "The period of max calls for the Cloud Asset API (in seconds)"
  default     = "1.0"
}

variable "cloudasset_disable_polling" {
  description = "Whether to disable polling for Cloud Asset API"
  default     = "False"
}

variable "cloudbilling_max_calls" {
  description = "Maximum calls that can be made to Cloud Billing API"
  default     = "5"
}

variable "cloudbilling_period" {
  description = "The period of max calls for the Cloud Billing API (in seconds)"
  default     = "1.2"
}

variable "cloudbilling_disable_polling" {
  description = "Whether to disable polling for Cloud Billing API"
  default     = "False"
}

variable "compute_max_calls" {
  description = "Maximum calls that can be made to Compute API"
  default     = "18"
}

variable "compute_period" {
  description = "The period of max calls for the Compute API (in seconds)"
  default     = "1.0"
}

variable "compute_disable_polling" {
  description = "Whether to disable polling for Compute API"
  default     = "False"
}

variable "container_max_calls" {
  description = "Maximum calls that can be made to Container API"
  default     = "9"
}

variable "container_period" {
  description = "The period of max calls for the Container API (in seconds)"
  default     = "1.0"
}

variable "container_disable_polling" {
  description = "Whether to disable polling for Container API"
  default     = "False"
}

variable "crm_max_calls" {
  description = "Maximum calls that can be made to CRN API"
  default     = "4"
}

variable "crm_period" {
  description = "The period of max calls for the CRM  API (in seconds)"
  default     = "1.2"
}

variable "crm_disable_polling" {
  description = "Whether to disable polling for CRM API"
  default     = "False"
}

variable "iam_max_calls" {
  description = "Maximum calls that can be made to IAM API"
  default     = "90"
}

variable "iam_period" {
  description = "The period of max calls for the IAM API (in seconds)"
  default     = "1.0"
}

variable "iam_disable_polling" {
  description = "Whether to disable polling for IAM API"
  default     = "False"
}

variable "logging_max_calls" {
  description = "Maximum calls that can be made to Logging API"
  default     = "9"
}

variable "logging_period" {
  description = "The period of max calls for the Logging API (in seconds)"
  default     = "1.0"
}

variable "logging_disable_polling" {
  description = "Whether to disable polling for Logging API"
  default     = "False"
}

variable "securitycenter_max_calls" {
  description = "Maximum calls that can be made to Security Center API"
  default     = "1"
}

variable "securitycenter_period" {
  description = "The period of max calls for the Security Center API (in seconds)"
  default     = "1.1"
}

variable "securitycenter_disable_polling" {
  description = "Whether to disable polling for Security Center API"
  default     = "False"
}

variable "servicemanagement_max_calls" {
  description = "Maximum calls that can be made to Service Management API"
  default     = "2"
}

variable "servicemanagement_period" {
  description = "The period of max calls for the Service Management API (in seconds)"
  default     = "1.1"
}

variable "servicemanagement_disable_polling" {
  description = "Whether to disable polling for Service Management API"
  default     = "False"
}

variable "sqladmin_max_calls" {
  description = "Maximum calls that can be made to SQL Admin API"
  default     = "1"
}

variable "sqladmin_period" {
  description = "The period of max calls for the SQL Admin API (in seconds)"
  default     = "1.1"
}

variable "sqladmin_disable_polling" {
  description = "Whether to disable polling for SQL Admin API"
  default     = "False"
}

variable "storage_disable_polling" {
  description = "Whether to disable polling for Storage API"
  default     = "False"
}

variable "cai_api_timeout" {
  description = "Timeout in seconds to wait for the exportAssets API to return success."
  default     = "3600"
}

variable "inventory_retention_days" {
  description = "Number of days to retain inventory data."
  default     = "-1"
}

#-------------------------------#
# Forseti server config scanner #
#-------------------------------#
variable "audit_logging_enabled" {
  description = "Audit Logging scanner enabled."
  default     = "false"
}

variable "bigquery_enabled" {
  description = "Big Query scanner enabled."
  default     = "true"
}

variable "blacklist_enabled" {
  description = "Audit Logging scanner enabled."
  default     = "true"
}

variable "bucket_acl_enabled" {
  description = "Bucket ACL scanner enabled."
  default     = "true"
}

variable "cloudsql_acl_enabled" {
  description = "Cloud SQL scanner enabled."
  default     = "true"
}

variable "config_validator_enabled" {
  description = "Config Validator scanner enabled."
  default     = "false"
}

variable "enabled_apis_enabled" {
  description = "Enabled APIs scanner enabled."
  default     = "false"
}

variable "firewall_rule_enabled" {
  description = "Firewall rule scanner enabled."
  default     = "true"
}

variable "forwarding_rule_enabled" {
  description = "Forwarding rule scanner enabled."
  default     = "false"
}

variable "group_enabled" {
  description = "Group scanner enabled."
  default     = "true"
}

variable "iam_policy_enabled" {
  description = "IAM Policy scanner enabled."
  default     = "true"
}

variable "iap_enabled" {
  description = "IAP scanner enabled."
  default     = "true"
}

variable "instance_network_interface_enabled" {
  description = "Instance network interface scanner enabled."
  default     = "false"
}

variable "ke_scanner_enabled" {
  description = "KE scanner enabled."
  default     = "false"
}

variable "ke_version_scanner_enabled" {
  description = "KE version scanner enabled."
  default     = "true"
}

variable "kms_scanner_enabled" {
  description = "KMS scanner enabled."
  default     = "true"
}

variable "lien_enabled" {
  description = "Lien scanner enabled."
  default     = "true"
}

variable "location_enabled" {
  description = "Location scanner enabled."
  default     = "true"
}

variable "log_sink_enabled" {
  description = "Log sink scanner enabled."
  default     = "true"
}

variable "resource_enabled" {
  description = "Resource scanner enabled."
  default     = "true"
}

variable "service_account_key_enabled" {
  description = "Service account key scanner enabled."
  default     = "true"
}

#--------------------------------#
# Forseti server config notifier #
#--------------------------------#
variable "violations_slack_webhook" {
  description = "Slack webhook for any violation. Will apply to all scanner violation notifiers."
  default     = ""
}

variable "iam_policy_violations_should_notify" {
  description = "Notify for IAM Policy violations"
  default     = "true"
}

variable "iam_policy_violations_slack_webhook" {
  description = "Slack webhook for IAM Policy violations"
  default     = ""
}

variable "audit_logging_violations_should_notify" {
  description = "Notify for Audit logging violations"
  default     = "true"
}

variable "blacklist_violations_should_notify" {
  description = "Notify for Blacklist violations"
  default     = "true"
}

variable "bigquery_acl_violations_should_notify" {
  description = "Notify for BigQuery ACL violations"
  default     = "true"
}

variable "buckets_acl_violations_should_notify" {
  description = "Notify for Buckets ACL violations"
  default     = "true"
}

variable "cloudsql_acl_violations_should_notify" {
  description = "Notify for CloudSQL ACL violations"
  default     = "true"
}

variable "config_validator_violations_should_notify" {
  description = "Notify for Config Validator violations."
  default     = "true"
}

variable "enabled_apis_violations_should_notify" {
  description = "Notify for enabled APIs violations"
  default     = "true"
}

variable "firewall_rule_violations_should_notify" {
  description = "Notify for Firewall rule violations"
  default     = "true"
}

variable "forwarding_rule_violations_should_notify" {
  description = "Notify for forwarding rule violations"
  default     = "true"
}

variable "ke_version_violations_should_notify" {
  description = "Notify for KE version violations"
  default     = "true"
}

variable "ke_violations_should_notify" {
  description = "Notify for KE violations"
  default     = "true"
}

variable "kms_violations_should_notify" {
  description = "Notify for KMS violations"
  default     = "true"
}

variable "kms_violations_slack_webhook" {
  description = "Slack webhook for KMS violations"
  default     = ""
}

variable "groups_violations_should_notify" {
  description = "Notify for Groups violations"
  default     = "true"
}

variable "instance_network_interface_violations_should_notify" {
  description = "Notify for instance network interface violations"
  default     = "true"
}

variable "iap_violations_should_notify" {
  description = "Notify for IAP violations"
  default     = "true"
}

variable "lien_violations_should_notify" {
  description = "Notify for lien violations"
  default     = "true"
}

variable "location_violations_should_notify" {
  description = "Notify for location violations"
  default     = "true"
}

variable "log_sink_violations_should_notify" {
  description = "Notify for log sink violations"
  default     = "true"
}

variable "resource_violations_should_notify" {
  description = "Notify for resource violations"
  default     = "true"
}

variable "service_account_key_violations_should_notify" {
  description = "Notify for service account key violations"
  default     = "true"
}

variable "external_project_access_violations_should_notify" {
  description = "Notify for External Project Access violations"
  default     = "true"
}

variable "cscc_violations_enabled" {
  description = "Notify for CSCC violations"
  default     = "false"
}

variable "cscc_source_id" {
  description = "Source ID for CSCC Beta API"
  default     = ""
}

variable "inventory_gcs_summary_enabled" {
  description = "GCS summary for inventory enabled"
  default     = "true"
}

variable "inventory_email_summary_enabled" {
  description = "Email summary for inventory enabled"
  default     = "true"
}

#---------------------------------------#
# Groups Settings scanner configuration #
#---------------------------------------#

variable "groups_settings_max_calls" {
  description = "Maximum calls that can be made to the G Suite Groups API"
  default     = "5"
}

variable "groups_settings_period" {
  description = "the period of max calls to the G Suite Groups API"
  default     = "1.1"
}

variable "groups_settings_disable_polling" {
  description = "Whether to disable polling for the G Suite Groups API"
  default     = "False"
}

variable "groups_settings_enabled" {
  description = "Groups settings scanner enabled."
  default     = "true"
}

variable "groups_settings_violations_should_notify" {
  description = "Notify for groups settings violations"
  default     = "true"
}

#----------------#
# Forseti client #
#----------------#
variable "client_type" {
  description = "GCE Forseti Client role instance size"
  default     = "n1-standard-2"
}

variable "client_boot_image" {
  description = "GCE Forseti Client role instance size"
  default     = "ubuntu-os-cloud/ubuntu-1804-lts"
}

variable "client_region" {
  description = "GCE Forseti Client role region size"
  default     = "us-central1"
}

variable "client_instance_metadata" {
  description = "Metadata key/value pairs to make available from within the client instance."
  type        = "map"
  default     = {}
}

variable "client_ssh_allow_ranges" {
  description = "List of CIDRs that will be allowed ssh access to forseti client"
  type        = "list"
  default     = ["0.0.0.0/0"]
}

variable "client_tags" {
  description = "GCE Forseti Client VM Tags"
  type        = "list"
  default     = []
}

variable "client_access_config" {
  description = "Client instance 'access_config' block"
  type        = "map"
  default     = {}
}

variable "client_private" {
  description = "Private GCE Forseti Client VM (no public IP)"
  default     = "false"
}

#------------#
# Forseti db #
#------------#
variable "cloudsql_region" {
  description = "CloudSQL region"
  default     = "us-central1"
}

variable "cloudsql_db_name" {
  description = "CloudSQL database name"
  default     = "forseti_security"
}

variable "cloudsql_db_port" {
  description = "CloudSQL database port"
  default     = "3306"
}

variable "cloudsql_proxy_arch" {
  description = "CloudSQL Proxy architecture"
  default     = "linux.amd64"
}

variable "cloudsql_type" {
  description = "CloudSQL Instance size"
  default     = "db-n1-standard-1"
}

#----------------#
# Forseti bucket #
#----------------#
variable "storage_bucket_location" {
  description = "GCS storage bucket location"
  default     = "us-central1"
}

variable "bucket_cai_location" {
  description = "GCS CAI storage bucket location"
  default     = "us-central1"
}

variable "bucket_cai_lifecycle_age" {
  description = "GCS CAI lifecycle age value"
  default     = "14"
}

#---------#
# Network #
#---------#
variable "network" {
  description = "The VPC where the Forseti client and server will be created"
  default     = "default"
}

variable "subnetwork" {
  description = "The VPC subnetwork where the Forseti client and server will be created"
  default     = "default"
}

variable "network_project" {
  description = "The project containing the VPC and subnetwork where the Forseti client and server will be created"
  default     = ""
}

#-------#
# Flags #
#-------#
variable "enable_write" {
  description = "Enabling/Disabling write actions"
  default     = "false"
}

variable "enable_cai_bucket" {
  description = "Create a GCS bucket for CAI exports"
  default     = "true"
}

#--------#
# Config #
#--------#
variable "org_id" {
  description = "GCP Organization ID that Forseti will have purview over"
  default = ""
}

variable "domain" {
  description = "The domain associated with the GCP Organization ID"
}

variable "folder_id" {
  description = "GCP Folder that the Forseti project will be deployed into"
  default     = ""
}

variable "composite_root_resources" {
  description = "A list of root resources that Forseti will monitor. This supersedes the root_resource_id when set."
  type        = "list"
  default     = []
}

variable "sendgrid_api_key" {
  description = "Sendgrid.com API key to enable email notifications"
  default     = ""
}
