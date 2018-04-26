---
title: Branch Methodology
order: 003
---

#  {{ page.title }}

This page describes the branches in the Forseti repository and how they're used
and managed.

## Branches

### Main Branches

These are the branches that the Forseti Security project team use
to do development, make releases, and build the website.

* `dev`: development branch
* `master`: latest stable release; suitable for deploy to production
* `forsetisecurity.org`: documentations for Forseti website.

The `dev` branch is the starting point where you can create a new PR,
and where the PR will be merged into the codebase after code review. Although
there are unit tests, the `dev` branch is still considered to be
unreliable because things can change before they're merged into the `master`
branch.

The `master` branch is checkpointed code from the `dev` branch that
has passed QA and integration testing. The `master` branch is considered
to be stable and suitable for production-use.

### Next-Generation Branches

Branches will be also be created, to develop the next-generation
of Forseti Security. These next-generation branches will be prefixed
with a version number.

Typically, the team will begin with a N.N-dev branch.  Once the the code reaches
a point for Early Access, the team will create and announce an eap branch,
e.g. N.N-eap1. Upon completion of an EAP phase the team will create
Release Candidates and encourage testing, e.g. N.N-rc1. Once all testing
requirements are satisfied the team will merge the completed code into N.N-dev
then into N.N-master, then into dev, and finally master.

An example of this workflow is described below for version 2.0:

2.0-dev: A daily development branch.
2.0-eap1: A branch used for Early Access testing.
2.0-rc1: A possible release candidate.
2.0-rc2: A second release candidate with additional changes.
2.0-master: latest stable release; suitable for deploy to production

After the support period has passed, the next-generation dev and master
branches will be merged into the `dev` and `master` branches. Then, the
`N.N-<name>` will be deleted. This way, `dev` and `master` are always
maintained as the canonical branches, and all the commit histories are retained.

### Other Branches

Other active branches in the Forseti repo are those created by other developers
to contribute to Forseti. You can generally disregard any branches that aren't
described above.

## Version Numbering Scheme

Forseti versions are denoted with X.Y.Z version numbering schema.
```
X signifies architectural changes.
Y signifies database schema changes.
Z signifies code changes.
```

The process below outlines how minor new 0.Y.Z point versions are managed.

1. When a new point version is ready to be released, either new 0.Y.0 version
or new 0.0.Z version, a new release branch will be created from the 
`dev` branch.

1. The release branch will undergo functional and integration testing.
If any bug is found, a new feature branch is created from the release branch,
go through code review, and merged back into the release branch.

1. When the release branch is fully qualified, the branch is merged into 
the `master` and `dev` branch.

1. The release branch is deleted.

## What's Next

* Learn how to [submit a Pull Request](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md).
* Learn about Forseti release process (TBD).
