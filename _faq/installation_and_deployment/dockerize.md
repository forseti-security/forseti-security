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

Dockerized Forseti Deployment
* Deploy Forseti Docker Image to a VM (e.g. Container-optimized OS)

* Running Forseti as short life GKE Cron Job
    * 
* Running Forseti as a long life GKE Service

