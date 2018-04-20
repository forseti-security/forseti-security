---
title: Forseti Architecture
order: 105
---

# {{ page.title }}

This page describes how Forseti is built, and how the components of Forseti fit
together.

Forseti gives you tools to understand all the resources you have in Google Cloud
Platform (GCP). The core Forseti modules work together to provide complete
information so you can take action to conserve resources, reduce cost, and
minimize security exposures.

 * Inventory regularly collects data from your GCP resources and makes it
   available to other modules.
 * Scanner periodically compares your rules about GCP resource policies against
   the policies collected by Inventory, and saves the output for your review.
 * Enforcer uses Google Cloud APIs to change resource policy state to match the
   state you define.
 * Notifier keeps you up to date about Forseti findings and actions.
 * Explain helps you understand, test, and develop Cloud Identity and Access
   Management (Cloud IAM) policies.

The image below shows how data flows through Forseti:

![Forseti module architecture diagram](/images/docs/concepts/forseti-architecture.png)

 1. Inventory collects information about your GCP resources and G Suite Groups.
 2. Inventory stores information in Cloud SQL for your review and use by other
    Forseti modules.
 3. Scanner compares the data collected by Inventory to the policy rules you
    set.
 4. Notifier sends Scanner findings to one or more of the following channels you
    configure: Cloud Storage, SendGrid, and Slack.
 5. You use Explain to check your Cloud IAM policies.
 6. Enforcer uses Google Cloud APIs to make sure policies match your desired
    state.
 7. You use the CLI to query Forseti data via GRPC.
 8. You use Data Studio or MySQL Workbench to visualize the Forseti data stored
    in CloudSQL.
