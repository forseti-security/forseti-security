---
title: Where are the logs stored for Forseti?
order: 3
---
{::options auto_ids="false" /}

The installation log is stored in `/tmp/deployment.log` on the Forseti 
Compute Engine instance.  You can view it with any editor.  For example:

```bash
vim /tmp/deployment.log
```

To find the Forseti Inventory, Scanner, and Enforcer logs:

1. Go to the Google Cloud Platform Console [Logs](https://console.cloud.google.com/logs/) page.
1. On the resources drop-down list, select **GCE VM Instance**.
1. On the **All logs** drop-down list, select **forseti**.
