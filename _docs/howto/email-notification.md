# Enabling Email Notifications

Forseti Security can send email notifications using the SendGrid API. SendGrid
is currently the only supported email service provider.

## Setting Up SendGrid

To use SendGrid to send email notifications for Forseti Security, follow the
process below:

  1. [Sign up for a SendGrid account](https://sendgrid.com/).
  1. Create a general [API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html).
  1. Edit your Google Cloud Deployment Manager (DM) template to update the
  following values in `deploy-forseti.yaml`:
    2. `SENDGRID_API_KEY`: the API key for SendGrid email service.
    2. `NOTIFICATION_SENDER_EMAIL`: sender email address for notifications
    2. `NOTIFICATION_RECIPIENT_EMAIL`: email address of notification recipient.

Note that SendGrid automatically includes an invisible tracking pixel in your
emails. This may cause email warnings about opening images. To disable this,
disable SendGrid [Open Tracking](https://sendgrid.com/docs/User_Guide/Settings/tracking.html#-Open-Tracking).
