# Contributing to Forseti

We welcome your patches and contributions to this project. This page describes
the few small guidelines we'll need you to follow.

## Submitting a Contributor License Agreement

Contributions to Forseti must be accompanied by a Contributor License Agreement
(CLA). The CLA gives us permission to use and redistribute your contributions
as part of the project. You or your employer retain the copyright to your
contribution. To see any CLA you currently have on file or sign a new one,
access [Contributor License Agreements](https://opensource.google.com/docs/cla/).

In most cases, you only need to submit a CLA once. If you've already submitted
a CLA for any project, you probably won't need to submit a new CLA.

## Following style guidelines and conventions

To maintain consistency, we ask that you follow the style guidelines suggested
in the
[Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
and any existing styles in the current codebase. Style is checked using pylint.
To confirm your pull request (PR) passes the Travis pylint test, the following
test must run without any output:

```bash
$ workon YOUR_VIRTUALENV

# Optional
$ pip install pylint

# From the root of forseti-security using pylint >= 1.6.5
$ PYTHONPATH=./ pylint --rcfile=./pylintrc
```
      
## Submitting a pull request

To submit a pull request for Forseti, follow the process below:

  1. Fork the project, clone your fork to your machine, and configure the
  upstream remote.
  
      ```bash
      # Fork the project via GitHub UI.
    
      # Clone your forked repository into a local directory.
      $ git clone FORKED_REPOSITORY_URL

      # Navigate to your the directory.
      $ cd <path to your directory from above>

      # Assign the original repository to a remote called "upstream".
      # Using HTTPS
      $ git remote add upstream https://github.com/GoogleCloudPlatform/forseti-security.git

      # Using SSH
      $ git remote add upstream git@github.com:GoogleCloudPlatform/forseti-security.git

      # Verify new upstream remote is added correctly.
      $ git remote -v

      origin  git@github.com:YOUR_FORK (fetch)
      origin  git@github.com:YOUR_FORK (push)
      upstream  git@github.com:GoogleCloudPlatform/forseti-security.git (fetch)
      upstream  git@github.com:GoogleCloudPlatform/forseti-security.git (push)
      ```

  1. Fetch the latest changes from upstream into your cloned repository:

      ```bash
      $ git fetch upstream
      $ git checkout dev
      $ git merge upstream/dev
      ```
    

  1. Create a new local development branch for your feature or bug fix:

      ```bash
      $ git checkout -b YOUR_DEVELOPMENT_BRANCH
      ```

  1. Create your change.

      - Don't incorporate multiple changes in one PR. A change should be a
      logical, self-contained unit of work, feature, or fix. This simplifies
      troubleshooting and rollbacks.
      - Learn how to execute
      [Inventory](https://forsetisecurity.org/docs/latest/use/cli/inventory.html),
      [Scanner](https://forsetisecurity.org/docs/latest/use/cli/scanner.html), or
      [Enforcer](https://forsetisecurity.org/docs/latest/use/cli/enforcer.html).

  1. Create tests for your change.

     - You should write applicable unit tests for your changes, especially for 
       changes involving substantial logic.
     - Learn how to
       [run the tests](https://forsetisecurity.org/docs/latest/develop/dev/testing.html).

  1. Commit your changes and push them to your development branch:

      ```bash
      $ git push origin YOUR_DEVELOPMENT_BRANCH
      ```

  1. Open a
  [pull request](https://help.github.com/articles/about-pull-requests/) to
  begin the code review.

      - All submissions, including submissions by project members, require a
      code review.
      - The Github UI will display whether you have any merge conflicts that
      need to be resolved.
      - All tests must pass before we review your PR. To ensure this happens we 
      recommend copying the `scripts/githooks` into your `.git/hooks`.

  1. After your PR is approved and all merge conflicts are resolved, we'll
  merge your PR.
