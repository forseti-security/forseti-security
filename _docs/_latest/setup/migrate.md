---
title: Migrate from Python Installer to Terraform Module
order: 600
---

# {{ page.title }}

This guide explains how to migrate a Forseti deployment from the
deprecated Python Installer to the new Terraform module.

If you have any
questions about this process, please contact us by
[email](mailto:discuss@forsetisecurity.org) or on
[Slack](https://join.slack.com/t/forsetisecurity/shared_invite/enQtOTM4NTkwMDcwMDA1LTk1ZDExYTExZTJlNjY3NjIwZmVhZmJkMjk3YzVhZmYwNGRmYmU0N2UzZDc2Njg4NmEwYWU4ODc3MWI3NjJkZTE).

---

A Cloud Shell walkthrough is provided to assist with migrating Forseti previously deployed with the Python installer.  Completing this guide will also result in a Forseti deployment upgraded to the most recent version.


[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fforseti-security%2Fterraform-google-forseti.git&cloudshell_git_branch=modulerelease510&cloudshell_working_dir=examples/migrate_forseti&cloudshell_image=gcr.io%2Fgraphite-cloud-shell-images%2Fterraform%3Alatest&cloudshell_tutorial=.%2Ftutorial.md)
