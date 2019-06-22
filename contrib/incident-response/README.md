# Open Source Incident Response Tools

This directory contains the ALPHA release of Terraform deployment scripts for open source incident response and digital forensics tools.
The first tool to be released is Timesketch.

**Note**: This is an early (alpha) release and the deployment is not fully polished yet. You are welcome to test it out and if you have any questions on how to use the tools please reach out to the official mailing lists as noted below.

**Note**: This setup will add billing costs to your project.

## Timesketch

Timesketch is an open source collaborative forensic timeline analysis tool. It uses full text search to give you insight into your timelines. You can search hundreds of millions of events across different timelines all at once. Share your findings using saved views and add meaning to your data with labels and comments. Bring life to your investigation with Timesketch Stories. Timesketch is build around collaboration, sharing and search.

* Project site: https://github.com/google/timesketch
* Mailing list: https://groups.google.com/forum/#!forum/timesketch-users

## GRR

GRR Rapid Response is an incident response framework focused on remote live forensics.

It consists of a python client (agent) that is installed on target systems, and python server infrastructure that can manage and talk to clients.

The goal of GRR is to support forensics and investigations in a fast, scalable manner to allow analysts to quickly triage attacks and perform analysis remotely.

* Project site: https://github.com/google/grr
* Mailing list: https://groups.google.com/forum/#!forum/grr-users

## Turbinia

Turbinia is an open-source framework for deploying, managing, and running distributed forensic workloads. It is intended to automate running of common forensic processing tools (i.e. Plaso, TSK, strings, etc) to help with processing evidence in the Cloud, scaling the processing of large amounts of evidence, and decreasing response time by parallelizing processing where possible.

* Project site: https://github.com/google/turbinia
* Mailing list: https://groups.google.com/forum/#!forum/turbinia-users

