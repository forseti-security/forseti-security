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

Following are the branches that the Forseti Security project team uses
for developing, creating releases, and building the website:

* `master`: The currently active development branch. The latest production release
  will be tagged with a version number.
* `forsetisecurity.org-dev`: The currently active development branch of the
  Forseti website.
* `forsetisecurity.org`: The latest deployed Forseti website.

The `master` branch is the starting point where you can create a new PR.
Although there are unit and integration tests, the `master` branch is still 
considered to be unreliable until the new features are tested as part
of the release process.

### Next-generation branches

Branches will be created to develop the next-generation versions of Forseti
Security. These next-generation branches will be prefixed with a version number.

Typically, the team will begin with an `N.N-master` branch. After the code
is developed so it's suitable for early testing, an Early Access Phase (EAP)
branch will be created, like `N.N-eap1`.

After the EAP is complete, a Release Candidate (RC) will be created, like
`N.N-rc1`. After all testing requirements are satisfied,
the team will merge the completed code into `master`.

Following is an example of this workflow for future versions:

* `3.0-master`: A daily development branch.
* `3.0-eap1`: A branch used for Early Access testing.
* `3.0-rc1`: A possible release candidate.
* `3.0-rc2`: A second release candidate with additional changes.
* `master`: The final released version of v2.0.

Before launching a new version, the existing `master` will be moved
and renamed as `(N-1).0-master`. For example, when a future version 3.0 is 
ready to be launched:

```
# Change the existing master branch to be the deprecated release branch.
master --> 2.0-master

# Change the new version's master branch to be the active development branch.
3.0-master --> master
```

### Other branches

Other active branches in the Forseti repo are those created by other developers
to contribute to Forseti. You can generally disregard any branches that aren't
described above.

## Version numbering scheme

Forseti version number scheme follows the [Semantic Versioning defined by semver.org](https://semver.org/),
and are denoted as `X.Y.Z`.  For example:

```
X signifies MAJOR changes, when architecture has changed.
Y signifies MINOR changes, when new features are added, along with bug fixes.
Z signifies PATCH changes, when only bug fixes are added.
```

The process below outlines how minor new `X.Y.Z` point versions are managed.

1. When a new point version is ready to be released, a new `x.Y.z` or `x.y.Z`
version will be created from the `master` branch.

1. The release branch will undergo functional and integration testing. Any bugs
found are fixed as follows:

   2. A new feature branch is created from the release branch.

   2. A code review is completed.

   2. The bug fix is merged back into the release branch.

1. When the release branch is fully qualified, the branch is merged into
the `master` branch.

1. After the release branch is merged, it's deleted.

## What's next

* Learn how to [submit a Pull Request](https://github.com/forseti-security/forseti-security/blob/master/.github/CONTRIBUTING.md).
