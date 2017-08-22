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

""" Crawler implementation. """


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


class CrawlerConfig(object):
    """The configuration profile of an inventory crawler"""
    def __init__(self, storage, progresser, api_client, variables=None):
        raise NotImplementedError('The configuration profile of an inventory crawler')

class Crawler(object):
    """The inventory crawler interface"""
    def run(self):
        """To start the crawler"""
        raise NotImplementedError('The run function of the crawler')

    def visit(self):
        """To visit a resource"""
        raise NotImplementedError('The visit function of the crawler')

    def dispatch(self):
        """To start a new visitor or continue"""
        raise NotImplementedError('The dispatch function of the crawler')

    def get_client(self):
        """Get the current API client"""
        raise NotImplementedError('The get_client function of the crawler')
