---
title: How often does Forseti scanning run?
order: 2
---
{::options auto_ids="false" /}

By default, Forseti runs Inventory and Scanner every 2 hours at random minutes,
using a simple cronjob. To change the cron value, edit the server's
[deployment template](https://github.com/forseti-security/forseti-security/blob/master-old/deployment-templates/compute-engine).
