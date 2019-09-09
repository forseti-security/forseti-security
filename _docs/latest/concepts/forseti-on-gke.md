---
title: Forseti on GKE
order: 006
---

{% include docs/latest/alpha-release-feature.md %}

# {{ page.title }}

This page describes the architecture of Forseti when deployed on the Google Kubernetes Engine (GKE).

---

## Deployment Architecture

In a traditional Forseti installation, the compute resources are deployed as GCE virtual machines (VM).  The Forseti server VM executes the forseti_server process, listening for requests to take action.  On the Forseti server is also a Linux cronjob that periodically invokes the server to build inventory and a model, scan, and notify on any violations.  The Forseti client VM provides a CLI where a user can invoke these same functions as well as execute the IAM explain function.

In Forseti on GKE, the core compute resources are deployed in containers: the server and orchestrator.  These containers are each wrapped in [Kubernetes Pods](https://kubernetes.io/docs/concepts/workloads/pods/pod/); the forseti-server and forseti-orchestrator pods respectively.  

The forseti-server pod is deployed in a [Kubernetes Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) controller.  Like the forseti_server process on the VM, this is a long running process that listens for requests made to it by a client.

The forseti-orchestrator pod is deployed in a [Kubernetes CronJob](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).  This reflects the behavior of the Linux cronjob on the server VM, periodically invoking the inventory build, scan, and notification actions on the forseti-server deployment.

The client CLI is still provided through the GCE VM.  The endpoint configuration for the the VM is set to send requests to the GCP load balancer for the Forseti server deployment.

This is illustrated in the following diagram.

{% responsive_image path: images/docs/concepts/forseti-on-gke-architecture.png alt: "forseti on GKE architecture" %}

## Container Strategy

### Container Images

The container images can be found in the following repositories

* [gcr.io/forseti-containers](https://console.cloud.google.com/gcr/images/forseti-containers/GLOBAL)
* [hub.docker.com/u/forsetisecurity](https://hub.docker.com/u/forsetisecurity)

The following describes the container image tags used in a Forseti on GKE installation.

{: .table}
|  Tag(s)  |  Description |
|----------|--------------|
| latest<br />v2.x.x | With each release of Forseti, a new container image is built with a tag corresponding to a tag in GitHub.  The latest release is also tagged with :latest. |
| dev | Every time a pull request is merged into the *dev* branch in GitHub, a new container image build is triggered resulting in an image with the :dev tag. |

### Container Builds

Forseti Security employs [multi-stage builds](https://docs.docker.com/develop/develop-images/multistage-build/) wherever possible for example the **forseti** image.  With multi-stage builds, container images can be built where the build-time dependencies are not necissarily present in the runtime container image.  The result is a smaller image for deployment.  The following image and chart describe each of the container image layers defined by the [Dockerfile](https://raw.githubusercontent.com/forseti-security/forseti-security/dev/Dockerfile)


{% responsive_image path: images/docs/concepts/forseti-gke-build-layers.png alt: "forseti container build layers" %}

## Helm Charts

[Helm](https://helm.sh/) is a package and application manager for Kubernetes.  Forseti uses Helm charts to manage the installation and upgrade of the Forseti application.  The [Forseti Helm charts](https://github.com/forseti-security/helm-charts) only deploy the Forseti Server and Forseti Orchestrator containers.  The Helm charts do not deploy the other components of Forseti (e.g. CloudSQL, GCS).





