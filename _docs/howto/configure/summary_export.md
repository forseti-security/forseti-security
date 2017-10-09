---
title: Export Summary Emails 
order: 205
---
# {{ page.title }}
This page describes how to create an AppScript to find, parse, and upload the
summary email dispatched from Forseti Security to BigQuery.


## Setting up configurations
1. First, create a filter in Gmail to automatically label the summary email,
e.g. "forseti".

1. Create an [AppScript](https://script.google.com/intro) with the following
function.

    ```js
    gmail_label = "forseti";
    message_subject = "Inventory Snapshot Complete";
    gcp_projectid = "" ;
    gcp_bigquery_datasetid = "";
    gcp_bigquery_tableid =  "";
    
    function GmailRead_forseti() {
      var label_pending = GmailApp.getUserLabelByName(gmail_label);
      var threads = label_pending.getThreads(0,3);
      
      for (var t in threads) {
       var thread = threads[t];
       var subject = thread.getMessages()[0].getSubject();
       var message = thread.getMessages()[0].getPlainBody();
       var dateofmessage = thread.getMessages()[0].getDate(); 
       var formattedDate = Utilities.formatDate(dateofmessage, "GMT", "yyyy-MM-dd'T'HH:mm:ss'Z'");
       var n = subject.indexOf(message_subject);
    
       if (n>=0) {
         var result = message.substring(message.indexOf("organizations")).replace(/ /g, ",").split(",\n").join("\n").slice(0, -1);
         var result = result.replace("Unknown", 0)
         var result = result.replace(/^/gm, formattedDate+",");
         Logger.log(result)
         var data = Utilities.newBlob(result, 'application/octet-stream')
         var job = {
           configuration: {
           load: {
           destinationTable: {
           projectId: gcp_projectid,
           datasetId: gcp_bigquery_datasetid,
           tableId: gcp_bigquery_tableid
           },
           skipLeadingRows: 0
           }
          }
         };
         job = BigQuery.Jobs.insert(job, gcp_projectid, data);
        }
      }
    }
    ```
1. Once saved obtain the project id from `Resources > Google Cloud Platform`
project and use that for the value of the `gcp_projectid` variable in the script.

    ```js
    ...
    gcp_projectid = "project-id-11111";
    ...
    ```
1. Next enable the BigQuery API for the project in two places.
    1. In the AppsScript at `Resources > Advanced Google Services`.
    1. In the API & Services of the GCP Project.
    
    Note that by default AppsScript creates projects outside the organization.
    To enable this API you will need to enable billing. This would be a good
    time to [migrate](https://cloud.google.com/resource-manager/docs/migrating-projects-billing)
    this project into an existing Organization.
    
1. Create a Bigquery Dataset and corresponding Table. Choose to create an empty
table and give it a name. Then choose the "Edit as Text" option specifying the
content below

    ```
    date:DATE,status:STRING,resource:STRING,count:INTEGER
    ```
1. Insert the values from the just created Dataset and Tables into the
`gcp_bigquery_datasetid` and `gcp_bigquery_projectid` variables of the script.

    ```js
    ...
    gcp_bigquery_datasetid = "forseti";
    gcp_bigquery_tableid= "summaries";
    ...
    ```

1. Configure trigger in Google App Script to launch every day in the
`Edit > Current Project's Triggers`.
