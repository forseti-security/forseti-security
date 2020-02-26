**branch: master** | **branch: forsetisecurity.org**
:------------ | :------------
[![Build Status](https://travis-ci.org/forseti-security/forseti-security.svg?branch=master)](https://travis-ci.org/forseti-security/forseti-security)|[![Build Status](https://travis-ci.org/forseti-security/forseti-security.svg?branch=forsetisecurity.org)](https://travis-ci.org/forseti-security/forseti-security)
[![codecov](https://codecov.io/gh/forseti-security/forseti-security/branch/master/graph/badge.svg)](https://codecov.io/gh/forseti-security/forseti-security)|

[More info on the branches.](https://forsetisecurity.org/docs/latest/develop/branch-management.html)

# Forseti Security
A community-driven collection of open source tools to improve the security of your Google Cloud Platform environments.

[Get Started](https://forsetisecurity.org/docs/latest/setup/install.html) with Forseti Security.

## Contributing
We are continually improving Forseti Security and invite you to submit feature requests and bug reports. If you would like to contribute to our development efforts, please review our [contributing guidelines](/.github/CONTRIBUTING.md) and submit a pull request.

### forsetisecurity.org
If you would like to contribute to forsetisecurity.org, the website and its content are contained in the `forsetisecurity.org-dev` branch. Visit its [README](https://github.com/forseti-security/forseti-security/tree/forsetisecurity.org-dev#forseti-security) for instructions on how to make changes.

## Governance
For information on how this project is managed and governed review our [governance](.github/GOVERNANCE.md) guidelines.

## Community 
Review our  [community page](http://forsetisecurity.org/community/) for ways to engage with the Forseti Community.

## Support
Support for the Forseti Security product can be obtained through a few channels: 
* Join the [Slack Channel](https://forsetisecurity.org/community/) and engage in discussions with other users and the Forseti community.
* Ask a question about Forseti and get community support by posting to (discuss@forsetisecurity.org). Posts can receive responses from the community or from engineers on the Forseti team. 
* File a GitHub [issue](https://github.com/forseti-security/forseti-security/issues/new). Issues are typically reviewed and triaged within 24 - 48 hours. 

## Releases
Product releases will occur on a quarterly schedule. An out of band patch release may occur but only for a critical defect or security issue. 
The team will support patching critical defects or security issues in the current release and in the  2 previous quarterly releases only. If a defect is found in a release beyond current - 2 customers are expected to upgrade to a current supported version of the product.

## Issue Triage
The triage process is a multi-step process that is collaboratively performed by the core project team and our issue bot. Triaging typically should occur within 1 - 2 business days, but may take longer, if the project team is not around.
The purpose of triaging is to clearly understand the request and determine the next steps for what will happen with your issue. 
It's straightforward to understand whether or not your issue is triaged: if the issue contains the *triaged :yes* label this indiacts the issue has been reviewed and classified by the project team.
In the case of a bug the a team member may request more details or information in order to better understand the problem, help determine prioritization or aid in reproducing the issue.
We close issues for the following reasons:
| Reason | Label |
| ------------- | ------------- |
| The issue is obsolete or already fixed. | N/A |
| We didn't get the information we needed within 7 days. | issue-review: need-more-information |
| Given the information we have we can't reproduce the issue or do not feel the issue necessitates a fix.  | issue-review: closed won't fix  |
| There has been activity on the issue for a significant period of time.  | stale |

###  Assigning  Milestones
In addition to [milestones](https://github.com/forseti-security/forseti-security/milestones]) representing our iterations for our product [releases](https://github.com/forseti-security/forseti-security/releases) we add additional labels that have special meaning:
*   `Backlog` Issue to be considered at some point in the future
*   `1 - Planning` Issues being considered for one of the next 3 iterations. The issue is on the short list to be assigned to a concrete iteration. 
*   `2 - Ready` Issue assigned and scheduled for a specific target milestone release
*   `3 - Work in progress` Issue is assigned to engineer and is actively working on the issue for targeted milestone release

## Pull Requests
The team and community encourages pull requests to fix issues or improve the product. Pull requests are typically reviewed within 48 hours of submission. 
If pull requests become inactive they will be automatically closed, but can be quickly and easily re-opened.
Please review the project’s contributing (guidelines)[.github/CONTRIBUTING.md] before submitting a pull request.
