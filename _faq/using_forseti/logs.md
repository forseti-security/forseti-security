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

The Forseti Inventory, Scanner, and Enforcer logs can be found in the Cloud 
Platform Console, under [Stackdriver](https://console.cloud.google.com/logs/). 
Change the first dropdown filter to "GCE VM Instance", and the second dropdown 
filter to "forseti".
