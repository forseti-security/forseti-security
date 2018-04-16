---
title: Branch Methodology
order: 003
---

#  {{ page.title }}

This page describes the branches in the Forseti repo and how they're used.

All active feature developments should be completed in the current General
Availability version, Forseti 2.0. Forseti 1.0 is on support-basis only,
and only bug fixes will be accepted.

## Branches

The branches listed below are the main branches you'll use to inspect
the correct codebase or create a Pull Request (PR):

* `dev`: development branch for Forseti 1.0
* `master`: latest stable release for Forseti 1.0.
* `forsetisecurity.org`: documentations for Forseti 1.0 website.

* `2.0-dev`: development branch for Forseti 2.0.
* `2.0-master`: latest stable release for Forseti 2.0.
* `2.0-forsetisecurity.org-dev`: documentations for Forseti 2.0 website.

A development branch is the starting point where you can create a new PR,
and where the PR will be merged into the codebase after code review. Although
there are unit tests, the development branch is still considered to be unstable
because functional and system tests are not yet complete.

A master branch is checkpointed code from the development branch that
has passed functional and system tests. The master branch is considered
to be stable and suitable for production-use.

Other active branches in the Forseti repo are those created by other developers
to contribute to Forseti. You can generally disregard any branches that aren't
explicitly listed above.

## Branching Methodology

The process below outlines how to manage your Forseti branches:

1. Identify the Forseti version to which you want to contribute.

1. Create your branch:

   1. Check out the appropriate development or documentation branch locally.
   
   1. Sync the branch to remote.

   1. Create a local feature branch to contain your change.

1. When you're finished making changes, push your local feature branch to remote.

1. Create a PR, and make sure the review base is on the appropriate remote
development or documentation branch for correct diffing and merging.

1. After the PR is merged, delete the remote and local feature branches.

## What's Next

* Learn how to [submit a Pull Request](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md).
