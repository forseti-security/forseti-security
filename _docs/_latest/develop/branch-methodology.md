---
title: Branch Methodology
order: 003
---

#  {{ page.title }}

## Branches

There are several important main branches in Forseti repo to know about,
in order to correctly inspect the right code, or create a Pull Request (PR).

* dev: development branch for Forseti 1.0.
* master: latest stable code for Forseti 1.0.
* forsetisecurity.org: documentations for Forseti 1.0 website.

* 2.0-dev: development branch for Forseti 2.0.
* 2.0-master: latest stable code for Forseti 2.0.
* 2.0-forsetisecurity.org-dev: documentations for Forseti 2.0 website.

Besides these main branches, you will also see other active branches.
Those branches will be other developer's work-in-progress, and can be
generally disregarded.

## Branching Methodology

1. Know the Forseti version that you want to make the change.

1. Depending on whether you want to make a code change or a documentation change,
checkout the appropriate development or documentation branch locally,
sync to remote, and create a local feature branch for your change.

1. Once you are done with your changes, you can push your local feature branch
to remote. 

1. Create a PR, and base it on the appropriate remote development
or documentation branch for correct diffing and merging.

1. Once the PR is merged, delete both the remote and local feature branches.

## What's Next

Learn how to [submit a Pull Request](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md).
