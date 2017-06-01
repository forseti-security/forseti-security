# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-

"""Internal pipeline to perform notifications"""

import jinja2
import json
from datetime import datetime
import requests

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.notifier.pipelines import base_notification_pipeline
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)

TEMP_DIR = '/tmp'
VIOLATIONS_JSON_FMT = 'violations.{}.{}.{}.json'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'

TEMPLATE = """
<!doctype html>
<html>
<head>
<style>
* {
  font-family: Arial, Helvetica, sans-serif;
  line-height: 16px;
}

a, a:visited {
  color: #1082d9;
}

.resource-violations tr > td {
  border: 1px solid #ddd;
  border: 1px solid #ddd;
  border-top: 0;
  border-bottom: 0;
  font-size: 14px;
  padding: 4px;
}

th {
  font-size: 16px;
  font-weight: bold;
  padding: 4px;
  text-align: left;
}

td {
  padding: 4px;
}

</style>
</head>
<body style="background-color: #eee;">
<div style="background-color: #fff; margin-top: 40px; padding: 20px; margin-left: 20%; margin-right: 20%;">
  <div style="margin: 10px 10px 15px 10px; font-size: 14px;">
    <p>
    Hello!<br />This is the Security team.<br />
    </p>

    <p>
    We are continously auditing GCP to detect security misconfigurations and you are receiving this email because
    we found one or more violations on a resource inside a GCP project you own.<br />
    </p>

    <p>
    Please take the time to review and resolve our findings and don't hesitate to get in touch if you need support.<br />
    You can reach us on the <strong>#security</strong> channel, or by email to security@spotify.com<br />
    </p>
    </hr>
    <p>
    The violations are categorized as "<em><strong>{{ resource }}</strong></em>" and were found during the scan on {{ scan_date }}.
    </p>
  </div>
  <div style="margin: 10px 10px;">
    <div style="font-style: italic; font-size: 14px; margin-bottom: 5px;">
      Owner:
      <ul>
       <li>{{ owner }}
      </ul>

      Affected projects:
      <ul>
        {% for v in violation_errors %}
        <li>{{ v }}</li>
        {% endfor %}
      </ul>
      <br />
      <p>See attached JSON for details.</p>
    </div>
    <div style="margin: 10px 10px 15px 10px; font-size: 14px;">

      <p>NOTE: we are experimenting on how to deliver notifications like this one, if you have some feedback please share!</p>

    </div>
  </div>

  <br/>

</div>

</body>
</html>
"""

class SpotifyPipeline(base_notification_pipeline.BaseNotificationPipeline):
    """Spotify pipeline to perform notifications"""

    def _get_clean_violation(self, violation):
        resource_type = violation['resource_type']

        resource_id = violation['resource_id']

        violation_project = {
            'project_id': None,
            'ownership': None,
            'violation': violation
        }

        if resource_type == 'project':
            violation_project['project_id'] = resource_id
            violation_project['ownership'] = self._get_project_ownership(
                resource_id)

        return violation_project

    def _get_project_ownership(self, project_id):
        # currently the bucket scanner includes propject_number isntead of
        # project_id, so I must make this method tolerant until a fix is pushed.
        # TODO: push a fix to bucket scanner to add project_id instenad of
        # project_number

        if project_id.isdigit():
            # assume the provided project_id is instead the project_number
            project_raw = self.project_dao.get_project_raw_data(
                'projects',
                self.cycle_timestamp,
                project_number=project_id)
        else:
            project_raw = self.project_dao.get_project_raw_data(
                'projects',
                self.cycle_timestamp,
                project_id=project_id)

        project_raw_d = json.loads(project_raw[0])

        ownership = {
            'project_id': None,
            'owner': None,
            'creator': None
        }

        p_labels = project_raw_d.get('labels')
        ownership['project_id'] = project_raw_d.get('projectId')
        if p_labels is not None:
            ownership['owner'] = p_labels.get('owner')
            ownership['creator'] = p_labels.get('creator')

        return ownership

    def __init__(self, resource, cycle_timestamp,
                 violations, notifier_config, pipeline_config):
        super(SpotifyPipeline, self).__init__(resource,
                                              cycle_timestamp,
                                              violations,
                                              notifier_config,
                                              pipeline_config)
        self.mail_util = EmailUtil(self.pipeline_config['sendgrid_api_key'])

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            The output filename for the violations json.
        """
        now_utc = datetime.utcnow()
        output_timestamp = now_utc.strftime(OUTPUT_TIMESTAMP_FMT)
        output_filename = VIOLATIONS_JSON_FMT.format(self.resource,
                                                     self.cycle_timestamp,
                                                     output_timestamp)
        return output_filename

    def _write_temp_attachment(self, **kwargs):
        """Write the attachment to a temp file.

        Returns:
            The output filename for the violations json just written.
        """

        violations_to_send = kwargs.get('violations')
        if violations_to_send is None:
            violations_to_send = self.clean_violations

        # Make attachment
        output_file_name = self._get_output_filename()
        output_file_path = '{}/{}'.format(TEMP_DIR, output_file_name)
        with open(output_file_path, 'w+') as f:
            f.write(json.dumps(violations_to_send, indent=4, sort_keys=True))
        return output_file_name

    def _make_attachment(self, **kwargs):
        """Create the attachment object.

        Returns:
            The attachment object.
        """
        output_file_name = self._write_temp_attachment(**kwargs)
        attachment = self.mail_util.create_attachment(
            file_location='{}/{}'.format(TEMP_DIR, output_file_name),
            content_type='text/json',
            filename=output_file_name,
            disposition='attachment',
            content_id='Violations'
        )

        return attachment

    def _make_body(self, template_vars):
        template_env = jinja2.Environment()
        template = template_env.from_string(TEMPLATE)
        return template.render(template_vars)

    def _make_content(self, **kwargs):
        """Create the email content.

        Returns:
            A tuple containing the email subject and the content
        """

        violations_to_send = kwargs.get('violations')
        if violations_to_send is None:
            violations_to_send = self.clean_violations

        timestamp = datetime.strptime(
            self.cycle_timestamp, '%Y%m%dT%H%M%SZ')
        pretty_timestamp = timestamp.strftime("%d %B %Y - %H:%M:%S")
        email_content = self._make_body({
                'scan_date':  pretty_timestamp,
                'resource': self.resource,
                'violation_errors': violations_to_send,
                'owner': kwargs.get('owner')
            })

        email_subject = '[ALERT] GCP Violations on projects you ({}) own - {}'.format(
            kwargs.get('owner'), pretty_timestamp)
        return email_subject, email_content

    def _compose(self, **kwargs):
        """Compose the email pipeline map

        Returns:
            Returns a map with subject, content, attachemnt
        """
        email_map = {}

        attachment = self._make_attachment(**kwargs)
        subject, content = self._make_content(**kwargs)
        to_address = kwargs.get('to')
        if to_address is None:
            to_address = self.pipeline_config['recipient']

        email_map['subject'] = subject
        email_map['content'] = content
        email_map['attachment'] = attachment
        email_map['recipient'] = to_address
        return email_map

    def _send(self, **kwargs):
        """Send a summary email of the scan.

        Args:
            subject: Email subject
            conetent: Email content
            attachment: Attachment object
        """
        notification_map = kwargs.get('notification')
        subject = notification_map['subject']
        content = notification_map['content']
        attachment = notification_map['attachment']

        self.mail_util.send(email_sender=self.pipeline_config['sender'],
                            email_recipient=notification_map['recipient'],
                            email_subject=subject,
                            email_content=content,
                            content_type='text/html',
                            attachment=attachment)


    def group_violations_by_owner(self):
        owners_map = {}
        for violation in self.clean_violations:
            violation_owner = violation['ownership']['owner']
            project_id = violation['ownership']['project_id']
            if owners_map.get(violation_owner) is None:
                owners_map[violation_owner] = {}

            if owners_map[violation_owner].get(project_id) is None:
                owners_map[violation_owner][project_id] = []

            owners_map[violation_owner][project_id].append(violation)

        return owners_map

    def run(self):
        """Run the email pipeline"""
        self.clean_violations = []

        for v in self.violations:
            self.clean_violations.append(self._get_clean_violation(v))

        mapped_violations = self.group_violations_by_owner()

        for owner in mapped_violations:
            print '%s@spotify.com' % owner
            if owner is None:
                owner_email = self.pipeline_config['recipient']
            else:
                owner_email = 'gianluca@spotify.com'
            email_notification = self._compose(owner=owner, to=owner_email, violations=mapped_violations[owner])
            self._send(notification=email_notification)
