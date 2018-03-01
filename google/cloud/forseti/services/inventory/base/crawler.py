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

"""Forseti Inventory Base Crawler Implementation."""


class CrawlerConfig(object):
    """The configuration profile of an inventory crawler"""

    pass


class Crawler(object):
    """The inventory crawler interface"""
    def run(self, resource):
        """To start the crawler, Not Implemented.

        Args:
            resource (object): Root resource to run on.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError('The run function of the crawler')

    def visit(self, resource):
        """To visit a resource, Not Implemented.

        Args:
            resource (object): Resource to visit.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError('The visit function of the crawler')

    def dispatch(self, callback):
        """Dispatch crawling of a subtree.

        Args:
            callback (function): Callback to dispatch.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError('The dispatch function of the crawler')

    def get_client(self):
        """Get the current API client, Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError('The get_client function of the crawler')
