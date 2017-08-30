---
title: How often does Forseti scanning run?
order: 2
---
{::options auto_ids="false" /}

By default, Forseti runs Inventory and Scanner on the top of every hour using a simple cronjob. You can edit the [deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/deployment-templates/compute-engine/forseti-instance.py#L183) to change this cron value.
