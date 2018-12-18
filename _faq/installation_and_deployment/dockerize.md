---
title: How to dockerize Forseti and deploy to COS/Kubernetes?
order: 11
---
{::options auto_ids="false" /}
Currently the Forseti docker image and COS/Kubernetes deployment are in experimental phase. It is available in the [github docker-poc branch](https://github.com/GoogleCloudPlatform/forseti-security/tree/docker-poc) -- collaboration welcomed! 


Prerequisites
All necessary GCP resources needs to be created and properly authorized. In the regular Forseti install, these resources are automatically taken care of. However, for dockerized Forseti such a process is not yet available. We suggest you do either of the following before deploying the docker image:
* Manually [setup your Forseti GCP infrastructure](https://forsetisecurity.org/docs/latest/develop/dev/setup.html#setting-up-gcp-infrastructure)
* (Quick Hack) Run the Forseti regular install just to create the GCP infrastructure

Please note that we recommend deploying Forseti to a dedicated cluster for now, because pod-based identity is not yet available (in progress).

Dockerized Forseti Deployment
* Deploy Forseti Docker Image to a VM (e.g. Container-optimized OS)
    * Please note that the cron job will be part of the docker image (?)
    * Deployment Steps:
        * #TODO

* Running Forseti as short-lived GKE Cron Job
    * Forseti and SQL proxy will each run in its own pod
    * Forseti will be hosted intermittently as a GKE Cron Job: when the scheduled cron job starts, a new pod is created to host Forseti and run the pre-defined cron job script; at the end of the cron job this pod is deleted
    * SQL proxy will be available at all time as a GKE Service
    * Deployment Steps: 
        * #TODO
* Running Forseti as a long-lived GKE Service
    * # TODO: details to be determined
