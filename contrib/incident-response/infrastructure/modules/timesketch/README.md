# Timesketch deployment

**Note**: This is an early (alpha) release and the deployment is not fully polished yet. You are welcome to test it out and if you have any questions on how to use the tools please reach out to the official mailing lists.

**Note**: This setup will add billing costs to your project.

Timesketch is an open source collaborative forensic timeline analysis tool. It uses full text search to give you insight into your timelines. You can search hundreds of millions of events across different timelines all at once. Share your findings using saved views and add meaning to your data with labels and comments. Bring life to your investigation with Timesketch Stories. Timesketch is build around collaboration, sharing and search.

* Project site: https://github.com/google/timesketch
* Mailing list: https://groups.google.com/forum/#!forum/timesketch-users

## The following resources will be created

* One GCE instance running the Timesketch server.
* Two (configurable) GCE instances running an Elasticsearch cluster.
* One Cloud SQL instance and databaser (PostgreSQL).
* One Redis instance.
