---
title: Enabling Email Notifications
order: 203
---
#  {{ page.title }}

Forseti Security can send email notifications using the SendGrid API. SendGrid
is the suggested free email service provider for Google Cloud Platform (GCP).
For information about how to get 12,000 free emails every month, see
[Sending Email with SendGrid](https://cloud.google.com/appengine/docs/standard/python/mail/sendgrid).

## Setting Up SendGrid

To use SendGrid to send email notifications for Forseti Security, follow the
process below:

1.  [Sign up for a SendGrid account](https://sendgrid.com/).
1.  Create a general
    [API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html).
1.  Edit the following in `forseti_conf.yaml`:
    1. `email_recipient`: email address of notification recipient.
    1. `email_sender`: sender email address for notifications
    1. `sendgrid_api_key`: the API key for SendGrid email service.

Note that SendGrid automatically includes an invisible tracking pixel in your
emails. This may cause email warnings about opening images. To disable this,
disable SendGrid
[Open Tracking](https://sendgrid.com/docs/User_Guide/Settings/tracking.html#-Open-Tracking).
