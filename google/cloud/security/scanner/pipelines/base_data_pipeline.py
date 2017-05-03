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

"""Base data pipeline skeleton."""

import abc

from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class BaseDataPipeline(object):
	"""This is a base class skeleton for data retrival pipelines"""
	__metaclass__ = abc.ABCMeta

	def __init__(self, snapshot_timestamp):
		"""Constructor for the base pipeline.

		Args:
		    cycle_timestamp: String of timestamp, formatted as

		Returns:
		    None
		"""
		self.snapshot_timestamp = snapshot_timestamp

	@abc.abstractmethod
	def run(self):
		"""Runs the pipeline."""
		pass

	@abc.abstractmethod
	def find_violations(self):
		"""Find violations."""
		pass
