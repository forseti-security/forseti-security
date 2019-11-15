---
title: Migrate from Python Installer to Terraform Module
order: 007
---

# {{ page.title }}

This guide explains how to migrate a Forseti deployment from the
deprecated Python Installer to the new Terraform module.

If you have any
questions about this process, please contact us by
[email](mailto:discuss@forsetisecurity.org) or on
[Slack](https://forsetisecurity.slack.com/join/shared_invite/enQtNDIyMzg4Nzg1NjcxLTM1NTUzZmM2ODVmNzE5MWEwYzAwNjUxMjVkZjhmYWZiOGZjMjY3ZjllNDlkYjk1OGU4MTVhZGM4NzgyZjZhNTE).

---

A Cloud Shell walkthrough is provided to assist with migrating Forseti previously deployed with the Python installer.  Completing this guide will also result in a Forseti deployment upgraded to the most recent version.

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fforseti-security%2Fterraform-google-forseti.git&cloudshell_git_branch=modulerelease510&cloudshell_working_dir=examples/migrate_forseti&cloudshell_image=gcr.io%2Fgraphite-cloud-shell-images%2Fterraform%3Alatest&cloudshell_tutorial=.%2Ftutorial.md)