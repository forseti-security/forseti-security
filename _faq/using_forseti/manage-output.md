---
title: How can I manage the output that Forseti writes to my Cloud Storage bucket that was configured as part of the installation?
order: 4
---
{::options auto_ids="false" /}

You can implement 
[bucket lifecycle](https://cloud.google.com/storage/docs/xml-api/put-bucket-lifecycle) 
rules to delete the output or migrate them to a lower cost class. 
Alternatively, you may wish to export the output to BigQuery.
