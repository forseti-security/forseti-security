---
title: Export Summary Notifications 
order: 206
---
# {{ page.title }}
This page describes how to create an AppScript to find, parse, and upload the
summary email dispatched from Forseti Security to BigQuery.

## Before you begin
To complete this guide, you'll need the following:

- A Google Cloud Platform (GCP)
  [Organization resource](https://cloud.google.com/resource-manager/docs/creating-managing-organization).
- A Forseti Security installation with
  [email notifications](http://forsetisecurity.org/docs/howto/configure/email-notification) enabled.
- A GCP project with the
  [BigQuery API enabled](https://console.cloud.google.com/flows/enableapi?apiid=bigquery) and
  [billing enabled](https://cloud.google.com/billing/docs/how-to/modify-project#enable_billing_for_a_project).

## Setting up configurations
### Filtering your email notifications
[Create a Gmail filter](https://support.google.com/mail/answer/6579) to
automatically label email that has the subject "Inventory Snapshot Complete."
You can use a simple label name like "Forseti."

### Creating an AppScript project
1. Create an [AppScript](https://script.google.com/intro) project with the
   following function, and save it with a temporary name.

    ```js
    gmail_label = "forseti";
    message_subject = "Inventory Snapshot Complete";
    gcp_projectname = "" ;
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
               projectId: gcp_projectname,
               datasetId: gcp_bigquery_datasetid,
               tableId: gcp_bigquery_tableid
               },
             skipLeadingRows: 0
             }
           }
         };
         job = BigQuery.Jobs.insert(job, gcp_projectname, data);
        }
        Logger.log('Load job started. Check on the status of it here: ' +
          'https://bigquery.cloud.google.com/jobs/%s', gcp_projectname);
      }
    }
    ```
1. Migrate the temporary AppScript project to your GCP project:
    1. Select **Resources > Cloud Platform project**.
    1. On the **Cloud Platform project** dialog that appears, paste your
       GCP Project ID, then click **Set Project**.
1.  In your AppScript project, paste your GCP Project ID as the `gcp_projectname`
    variable value:

    ```js
    ...
    gcp_projectname = "your_project_id";
    ...
    ```
1. Enable the BigQuery API for the AppScript project under
   **Resources > Advanced Google Services**.    

### Creating a BigQuery dataset and table
1. Go to [BigQuery](https://bigquery.cloud.google.com/welcome/) and select
   the project you're using for this guide.
1. On the project menu, click **Create new dataset** and type a name in the
   **Dataset ID** box, then click **OK**.
1. On the dataset menu, click **Create new table**.
1. In the **Create Table** panel that appears, select **Create empty table**
   next to **Source Data**.
1. Add a **Destination table name**.
1. Under **Schema**, click **Edit as Text**. In the box that appears, paste
   the following:

    ```
    date:STRING,status:STRING,resource:STRING,count:INTEGER
    ```
1. Click **Create Table**.

### Configuring the AppScript project
1. In your AppScript project, paste the names of the dataset and table you
   created as the values for the `gcp_bigquery_datasetid` and `gcp_bigquery_tabletid`
   variables:

    ```js
    ...
    gcp_bigquery_datasetid = "your_dataset_id";
    gcp_bigquery_tableid= "your_table_id";
    ...
    ```
1. Configure the script to run daily:
    1. Select **Edit > Current project's triggers**.
    1. Click to add a new trigger.
    1. On the **Hour timer** dropdown, select **Day timer**.
    1. On the time dropdown, select the time you want the script to run, then
       click **Save**.

The script will now run at the time you selected and export details from the Forseti
notification email to BigQuery.
