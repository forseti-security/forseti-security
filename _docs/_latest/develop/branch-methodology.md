---
title: Branch Methodology
order: 003
---

#  {{ page.title }}

This page describes the branches in the Forseti repo and how they're used
and managed.

## Branches

### General Availability (GA) Branches

GA branches are the main branches you'll use to inspect the currently stable &
production-ready codebase, create a Pull Request (PR), or deploy to production.

* `dev`: development branch
* `master`: latest stable release; suitable for deploy to production
* `forsetisecurity.org`: documentations for Forseti website.

The `dev` branch is the starting point where you can create a new PR,
and where the PR will be merged into the codebase after code review. Although
there are unit tests, the development branch is still considered to be unstable
because functional and system tests are not yet complete.

The `master` branch is checkpointed code from the `dev` branch that
has passed functional and system tests. The `master` branch is considered
to be stable and suitable for production-use.

### Next-Generation Branches

Branches will be also be created, to contain the development for the
next-generation of Forseti.  These next-generation branches will be prefixed
with a version number.

Examples of the next-generation branches:
```
* 2.0-dev: development branch
* 2.0-eap1: early evaluation; end-to-end workflow complete
* 2.0-rc1: release candidate 1; feature complete
* 2.0-rc2: release candidate 2; final schema changes
* 2.0-master: latest stable release; suitable for deploy to production
* 2.0-forsetisecurity.org: documentations for Forseti website.
```

After the support period has passed, the next-generation dev and master
branches will be merged into the `dev` and `master` branches. Then, the
`N.0-<branches>` will be deleted.  This way, `dev` and `master` are always
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
