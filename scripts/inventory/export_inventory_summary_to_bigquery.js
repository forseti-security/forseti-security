/*
This script is contributed by Antoine Castex <antoine-castex>

This is a Cloud Function Script to upload inventory summary to bigquery.
Documentation on how to use Cloud Function can be found here:
https://cloud.google.com/functions/

Here is the package:
{
  "name": "function-from-gcs-to-bq",
  "version": "0.0.1",
  "dependencies": {
    "@google-cloud/bigquery": "1.2.0",
    "@google-cloud/storage": "1.2.1",
    "parse-json": "4.0.0"
  }
}
*/

exports.getData = (event) => {
  console.log("--- BEGIN ---")
  const file = event.data;
  const context = event.context;
  const parseJson = require('parse-json');
  const Storage = require('@google-cloud/storage');
  const BigQuery = require('@google-cloud/bigquery');
  const bigquery = new BigQuery({
  projectId: 'big-query-project',
});
  const dataset = bigquery.dataset('report');
  const table = dataset.table('gcp_usage');
  const bucketName = file.bucket;
  const filename = file.name;
  const storage = new Storage({
  projectId: 'gcs-project'
});
  const data = storage.bucket(bucketName).file(filename);
  console.log(data)
  console.log("--- LOAD ---")

  data.download( function(err, contents) {
      console.log(JSON.parse(contents));
      var array = JSON.parse(contents)
      for (a in array) {
        console.log(array[a])
        var number = array[a].count
        var resource = array[a].resource_type
        var date = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '')
        var date2 = new Date().toISOString()
		console.log("date is "+date2)
        var jsn = {
  			Resource_Name: resource,
            Status: 'SUCCESS',
            Quantity: number,
  			Date: new Date().toISOString()}
        console.log("--- JSON Ready ---")
        console.log(jsn)
        table.insert(jsn);
      }

    } );
  console.log("--- END ---")
};
