---
title: Architecture
order: 001
---

# {{ page.title }}

This page describes how Forseti is built, and how the components of Forseti fit
together.

---

Overview

Forseti gives you tools to understand all the resources you have in Google Cloud
Platform (GCP). The core Forseti modules work together to provide complete
information so you can take action action to secure resources and minimize
security risks.

 * Inventory regularly collects data from your GCP resources and makes it
   available to other modules.
 * Scanner periodically compares your rules about GCP resource policies against
   the policies collected by Inventory, and saves the output for your review.
 * Enforcer uses Google Cloud APIs to change resource policy state to match the
   state you define.
 * Notifier keeps you up to date about Forseti findings and actions.
 * Explain helps you understand, test, and develop Cloud Identity and Access
   Management (Cloud IAM) policies.

---

**The image below shows how data flows through Forseti**

{% responsive_image path: images/docs/concepts/forseti-architecture.png alt: "forseti architecture" %}

 A. Inventory collects information about your GCP resources and G Suite Groups and Users.
 B. Inventory stores information in Cloud SQL for your review and use by other
    Forseti modules.
 C. Scanner compares the data collected by Inventory to the policy rules you
    set.
 D. Notifier sends Scanner & Inventory results to one or more of the following channels you
    configure: Cloud Storage, SendGrid, and Slack.
 E. You use Explain to query and understand your Cloud IAM policies.
 F. Enforcer uses Google Cloud APIs to make sure policies match your desired
    state.
 G. You use the command-line interface to query Forseti data via GRPC.
 H. You use Data Studio or MySQL Workbench to visualize the Forseti data stored
    in CloudSQL.
