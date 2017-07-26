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


from google.cloud.security.crawler import progress
from google.cloud.security.crawler import storage
from google.cloud.security.crawler import resources
from google.cloud.security.crawler import gcp


class CrawlerConfig(dict):
    def __init__(self, storage, progresser, api_client, variables={}):
        self.storage = storage
        self.progresser = progresser
        self.variables = variables


class Crawler(object):
    def __init__(self, config):
        self.config = config

    def run(self, resource):
        resource.accept(self)

    def visit(self, resource):
        storage = self.config.storage
        try:
            storage.write(resource)
        except Exception as e:
            progresser.on_error(e)

        progresser = self.config.progresser
        progresser.on_new_object(resource)


if __name__ == '__main__':
    orgid = 'fuubar'

    client = gcp.ApiClient()
    mem = storage.Memory()
    progresser = progress.CliProgresser()
    config = CrawlerConfig(mem, progresser)

    crawler = Crawler(config)
    progresser = crawler.run(resources.Organization(orgid))
    progresser.print_stats()
