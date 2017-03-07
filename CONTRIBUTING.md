# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

* [Contributor License Agreement](#contributor-license-agreement)
* [Style Guideline and Conventions](#style-guideline-and-conventions)
* [How to Create A Pull Request](#how-to-create-a-pull-request)
* [Contact Us](#contact-us)

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution,
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Style Guideline and Conventions

In order to maintain consistency, style guidelines as suggested by the
[Google Python Style Guide] should be followed, as well as conforming to
the existing styles in the current codebase.

## How to Create A Pull Request

1. Consult [GitHub Help] for more information on using pull requests.

2. Fork the project, clone your fork to a local repository, and configure
the upstream remote.

    ```
    # Fork the project via GitHub UI.

    # Clone your forked repository into local directory.
    $ git clone <url of forked repository>

    # Navigate to your newly cloned directory.
    $ cd <path to you local cloned repository>
    
    # Assign the original repository to a remote called "upstream".
    # Using HTTPS
    $ git remote add upstream https://github.com/GoogleCloudPlatform/forseti-security.git
    
    # Using SSH
    $ git remote add upstream git@github.com:GoogleCloudPlatform/forseti-security.git
    
    # Verify new upstream remote is added correctly.
    $ git remote -v
    
    origin  git@github.com:<my_fork> (fetch)
    origin  git@github.com:<my_fork> (push)
    upstream  git@github.com:GoogleCloudPlatform/forseti-security.git (fetch)
    upstream  git@github.com:GoogleCloudPlatform/forseti-security.git (push)
    ```

3. Get the latest changes from the upstream origin into your
cloned repository.

    ```
    $ git fetch upstream
    $ git checkout master
    $ git merge upstream/master
    ```

4. Create a new local development branch that will contain your feature,
or bug fix.

    ```
    $ git checkout -b <my_development_branch>
    ```

5. Create your change.

    A change should be a logical, self-contained unit of work, feature, or fix.
    This way, it is easier for troubleshooting and rollbacks.  In other words,
    please do not incorporate multiple changes in one PR.
    
    [Instructions to execute the tools.]

6. Create your test.

    We strive to have high and useful coverage by unit tests.  If your change
    involves substantial logic, we will request that you write applicable unit
    tests.
    
    Our unit tests are written with google-apputils basetest framework.
    See a [basic example] of how to use it, in the "Google-Style Tests" section.
    
    [Instructions to run the tests.]

7. Commit your changes and push your development branch to your fork.

    ```
    $ git push origin <my_development_branch>
    ```

8. Open a Pull Request.

    Use the GitHub UI to open a pull request.  The GitHub UI will show you
    dropdowns to select the destination of the pull request:
    * the base fork is the upstream
    * the head fork is the user's fork
    
    All tests must pass before we will review the PR.

9. Code Reviews

    All submissions, including submissions by project members, require review.
    To begin the review process, create a new GitHub pull request.  The GitHub UI
    will show if there are any merge conflict(s) to be resolved.

10. Merging your PR.

    Once your PR is approved, we will merge your PR.  Make sure any merge
    conflict(s) is resolved, if necessary.  We will use the "Squash and Commit"
    option for merging your PR.  This allows us to squash down your commit
    histories, and merge with one clean commit.

## Contact Us
Reach out to us with questions by contacting
[forseti-security@google.com].

[GitHub Help]: https://help.github.com/articles/about-pull-requests/
[Google Python Style Guide]: https://google.github.io/styleguide/pyguide.html
[Instructions to execute the tools.]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/README.md#execution
[basic example]: https://pypi.python.org/pypi/google-apputils
[Instructions to run the tests.]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/README.md#tests
[forseti-security@google.com]: mailto:forseti-security@google.com
