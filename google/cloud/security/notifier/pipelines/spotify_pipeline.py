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

"""Internal pipeline to perform notifications"""

import json
from datetime import datetime

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

    def _write_temp_attachment(self):
        """Write the attachment to a temp file.

        Returns:
            The output filename for the violations json just written.
        """
        # Make attachment
        output_file_name = self._get_output_filename()
        output_file_path = '{}/{}'.format(TEMP_DIR, output_file_name)
        with open(output_file_path, 'w+') as f:
            f.write(parser.json_stringify(self.clean_violations))
        return output_file_name

    def _make_attachment(self):
        """Create the attachment object.

        Returns:
            The attachment object.
        """
        output_file_name = self._write_temp_attachment()
        attachment = self.mail_util.create_attachment(
            file_location='{}/{}'.format(TEMP_DIR, output_file_name),
            content_type='text/json',
            filename=output_file_name,
            disposition='attachment',
            content_id='Violations'
        )

        return attachment

    def _make_content(self):
        """Create the email content.

        Returns:
            A tuple containing the email subject and the content
        """
        timestamp = datetime.strptime(
            self.cycle_timestamp, '%Y%m%dT%H%M%SZ')
        pretty_timestamp = timestamp.strftime("%d %B %Y - %H:%M:%S")
        email_content = self.mail_util.render_from_template(
            'notification_summary.jinja', {
                'scan_date':  pretty_timestamp,
                'resource': self.resource,
                'violation_errors': self.clean_violations,
            })

        email_subject = 'Forseti Violations {} - {}'.format(
            pretty_timestamp, self.resource)
        return email_subject, email_content

    def _compose(self, **kwargs):
        """Compose the email pipeline map

        Returns:
            Returns a map with subject, content, attachemnt
        """
        email_map = {}

        attachment = self._make_attachment()
        subject, content = self._make_content()
        email_map['subject'] = subject
        email_map['content'] = content
        email_map['attachment'] = attachment
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
                            email_recipient=self.pipeline_config['recipient'],
                            email_subject=subject,
                            email_content=content,
                            content_type='text/html',
                            attachment=attachment)


    def run(self):
        """Run the email pipeline"""
        self.clean_violations = []

        for v in self.violations:
            self.clean_violations.append(self._get_clean_violation(v))
        email_notification = self._compose()
        self._send(notification=email_notification)
