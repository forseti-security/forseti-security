---
title: How do I keep Forseti VM instances (client and server) up-to-date with security patches? 
order: 7
---
{::options auto_ids="false" /}


[GCE](https://cloud.google.com/compute/docs/images) VM instances have the 
[unattended-upgrades](https://wiki.debian.org/UnattendedUpgrades) tool to automatically update the operating system, software, or security patches from the [Debian security](https://www.debian.org/security/) repository.

However, kernel patches do not take effect until your VM instance is restarted.
By default, GCE does not automatically restart running instances.So you must either restart your instances manually to update the kernel, or [apply the mechanism provided by the unattended-upgrades tool to automatically do the restart](https://wiki.debian.org/UnattendedUpgrades#Automatic_call_via_.2Fetc.2Fapt.2Fapt.conf.d.2F20auto-upgrades).

Automatic updates from Debian security do not upgrade instances between major versions of the operating system.
Debian also has a relevant guide: https://www.debian.org/doc/manuals/securing-debian-howto/index.en.html

