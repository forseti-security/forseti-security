# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Base email connector to select connector"""

import abc
import os

import jinja2

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


class BaseEmailConnector(object):
    """Base email connector."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def _execute_send(self, email):
        """Executes the sending of the email.

        This needs to be a standalone method so that we can wrap it with retry,
        and the final exception can be gracefully handled upstream.

        Args:
            email (mail): Connector mail object

        Returns:
            dict: urllib2 response
        """
        pass

    @abc.abstractmethod
    def send(self, email_sender=None, email_recipient=None,
             email_subject=None, email_content=None, content_type=None,
             attachment=None):
        """Send an email.

        This uses specific connector authentication details.

        The minimum required info to send email are:
        sender, recipient, subject, and content (the body)

        Args:
            email_sender (str): The email sender.
            email_recipient (str): The email recipient.
            email_subject (str): The email subject.
            email_content (str): The email content (aka, body).
            content_type (str): The email content type.
            attachment (Attachment): An Email Connector Attachment.

        Raises:
            EmailSendError: An error with sending email has occurred.
        """
        pass

    @classmethod
    def render_from_template(cls, template_file, template_vars):
        """Fill out an email template with template variables.

        Args:
            template_file (str): The location of email template in filesystem.
            template_vars (dict): The template variables to fill into the
                template.

        Returns:
            str: The template content, rendered with the provided variables.
        """
        template_searchpath = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '../../email_templates'))
        template_loader = jinja2.FileSystemLoader(
            searchpath=template_searchpath)
        template_env = jinja2.Environment(loader=template_loader)
        template = template_env.get_template(template_file)
        return template.render(template_vars)
