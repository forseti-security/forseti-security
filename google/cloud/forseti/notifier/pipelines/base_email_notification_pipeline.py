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

"""Base email pipeline to perform notifications"""

import abc

from google.cloud.forseti.notifier.pipelines import (
    base_notification_pipeline as bnp)
from google.cloud.forseti.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class BaseEmailNotificationPipeline(bnp.BaseNotificationPipeline):
    """Base email pipeline."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def _send(self, **kwargs):
        """Send notifications.

        Args:
            **kwargs: Arbitrary keyword arguments.
        """
        pass

    @abc.abstractmethod
    def _compose(self, **kwargs):
        """Compose notifications.

        Args:
            **kwargs: Arbitrary keyword arguments.
        """
        pass
