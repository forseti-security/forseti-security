# How to contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution,
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Style Guideline & Conventions

In order to maintain consistency, style guidelines as suggested by the
[Google Python Style Guide] should be followed, as well as conforming to
the existing styles in the current codebase.

## Life of A Pull Request

0. Consult [GitHub Help] for more information on using pull requests.

1. Fork the project, clone your fork to a local repo, and configure
the upstream remote.

```
# Fork the project via GitHub UI.

# Clone your forked repo into local directory.
git clone <url of cloned repo>

# Navigate to your newly cloned directory.
cd <path to you local cloned repo>

# Assign the original repo to a remote called "upstream".
# https
git remote add upstream https://github.com/GoogleCloudPlatform/forseti-security.git

# ssh
git remote add upstream git@github.com:GoogleCloudPlatform/forseti-security.git

# Verify new upstream remote is added correctly.
$ git remote -v

origin  git@github.com:<my_fork> (fetch)
origin  git@github.com:<my_fork> (push)
upstream  git@github.com:GoogleCloudPlatform/forseti-security.git (fetch)
upstream  git@github.com:GoogleCloudPlatform/forseti-security.git (push)
```

2. Get the latest changes from upstream (the original repo) into your
cloned repo.

```
git fetch upstream
git checkout master
git merge upstream/master
```

3. Create a new local development branch that will contain your feature,
or bug fix.

```
git checkout -b <my_development_branch>
```

4. Create your change.

A change should be a logical, self-contained unit of work, feature, or fix.
This way, it is easier for troubleshooting and rollbacks.  In other words,
please do not incorporate multiple changes in one PR.

5. Create your test.

We strive to have high and useful coverage by unit tests.  If your change
involves substantial logic, we will require that you write a unit test.

6. Commit your changes and push your development branch to your fork.

You don't need to worry about making sure you have one clean commit as we
have enabled "Squash and Commit" on GitHub UI.

```
git push origin <my_development_branch>
```

8. Open a Pull Request.

All tests must be passing before we will review the PR.

9. Code Reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose.

10. Merging your PR.

Once your PR is approved, merge your PR, resolving any merge conflict
if necessary.  A nice feature that we have enabled on the GitHub UI is
"Squash and Commit".  This allows you to squash down your commit histories,
and you are merging with one clean commit.

If you have any additional questions, please create an issue in this repo.


[GitHub Help]: https://help.github.com/articles/about-pull-requests/
[Google Python Style Guide]: https://google.github.io/styleguide/pyguide.html
