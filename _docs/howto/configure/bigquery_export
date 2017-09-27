---
title: BigQuery Export
---

# {{ page.title }}

This page describes how to configure Forseti to export inventory result to BigQuery 

## Setting up configurations

- Setting a filter in Gmail mailbox to automatically label forseti email as : Forseti

- Create a Google App Script to :  parse forseti inventory email and put the result to BigQuery

Use this function :


function GmailRead_forseti() {
  var label_pending = GmailApp.getUserLabelByName("Forseti");
  var threads = label_pending.getThreads(0,3); 
  for (var t in threads) {
   var thread = threads[t];
   var subject = thread.getMessages()[0].getSubject();
   var message = thread.getMessages()[0].getPlainBody();
   var dateofmessage = thread.getMessages()[0].getDate(); 
   var formattedDate = Utilities.formatDate(dateofmessage, "GMT", "yyyy-MM-dd'T'HH:mm:ss'Z'");
   var n = subject.indexOf("Inventory Snapshot Complete");
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
       projectId: "xxxxx",
       datasetId: "report",
       tableId: "gcp_usage"
       },
       skipLeadingRows: 0
       }
      }
     };
     job = BigQuery.Jobs.insert(job, "gbl-imt-ve-billing", data);
    }
  }
}



- Configure trigger in Google App Script to lunch the script every day

- Create dataset and table in BigQuery, with autorisations needed to write on them

- Let's do this and visualize every day result in Google Data Studio
