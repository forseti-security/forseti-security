---
title: Branch Management 
order: 003
---

#  {{ page.title }}

This page describes the branches in the Forseti repository and how they're used
and managed.

---

## Branches

### Main branches

These are the branches that the Forseti Security project team use
for developing, creating releases, and building the website.

* `dev`: The currently active development branch.
* `stable`: The latest Forseti release suitable for deploy to production.

* `1.0-dev`: The deprecated development branch for Forseti 1.0;
this is for critical bug fixes only for the duration of 1.0 support.
* `master`: The latest Forseti 1.0 release suitable for deploy to production;
this is deprecated and should not be used for new installs.

* `forsetisecurity.org`: Forseti website.

The `dev` branch is the starting point where you can create a new PR. 
Although there are unit tests, the `dev` branch is still considered to be
unreliable because it can change before it's merged into the `master`
branch.

The `stable` branch is checkpointed code from the `dev` branch that
has passed QA and integration testing. The `stable` branch is considered
to be stable and suitable for production-use.

### Next-generation branches

Branches will be created to develop the next-generation versions of Forseti
Security. These next-generation branches will be prefixed with a version number.

Typically, the team will begin with an `N.N-dev` branch. After the code
is developed so it's suitable for early testing, an Early Access Phase (EAP)
branch will be created, like `N.N-eap1`.

After the EAP is complete, a Release Candidate (RC) will be created, like
`N.N-rc1`. After all testing requirements are satisfied,
the team will merge the completed code into `N.N-dev`, then into
`N.N-master`, then into `dev`, and finally `master`.

Following is an example of this workflow for future versions:

* `3.0-dev`: A daily development branch.
* `3.0-eap1`: A branch used for Early Access testing.
* `3.0-rc1`: A possible release candidate.
* `3.0-rc2`: A second release candidate with additional changes.
* `master`: The final released version of v2.0.

Before launching a new version, the existing `dev` and `master` will be moved
and renamed as `(N-1).0-dev` and `(N-1).0-master`. Existing `N.N-dev`
will be moved and renamed to `dev`. A new `master` branch will be created from
`dev` branch. This is so that the `dev` and `master` branches are always
maintained as the canonical branches, and all the commit histories and tags
are retained.

For example, when a future version 3.0 is ready to be launched:

```
# Make existing dev branch to be the deprecated development branch.
dev --> 2.0-dev

# Make existing master branch to be the deprecated release branch.
master --> 2.0-master

# Make the new version's dev branch to be the new active dev branch.
3.0-dev --> dev

# Create new active release branch from the new dev branch.
```

### Other branches

Other active branches in the Forseti repo are those created by other developers
to contribute to Forseti. You can generally disregard any branches that aren't
described above.

## Version numbering scheme

Forseti versions are denoted with an `X.Y.Z` version numbering schema, for example:

```
X signifies architectural changes.
Y signifies database schema changes.
Z signifies code changes.
```

The process below outlines how minor new `X.Y.Z` point versions are managed.

1. When a new point version is ready to be released, a new `x.Y.z` or `x.y.Z`
version will be created from the `dev` branch.

1. The release branch will undergo functional and integration testing. Any bugs
found are fixed as follows:

   2. A new feature branch is created from the release branch.
  
   2. A code review is completed.
  
   2. The bug fix is merged back into the release branch.

1. When the release branch is fully qualified, the branch is merged into 
the `stable` and `dev` branch.

1. After the release branch is merged, it's deleted.

## What's next

* Learn how to [submit a Pull Request](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md).
