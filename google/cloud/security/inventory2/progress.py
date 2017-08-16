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


class Progresser(object):
    def __init__(self):
        pass

    def on_new_object(self, resource):
        raise NotImplementedError()

    def on_warning(self, warning):
        raise NotImplementedError()

    def on_error(self, error):
        raise NotImplementedError()

    def get_summary(self):
        raise NotImplementedError()


class CliProgresser(object):
    def __init__(self):
        self.errors = []
        self.warnings = []

    def on_new_object(self, resource):
        print 'found new object: {}'.format(resource)

    def on_warning(self, warning):
        print 'warning: {}'.format(warning)
        self.warnings.append(warning)

    def on_error(self, error):
        print 'error: {}'.format(error)
        self.errors.append(error)

    def get_summary(self):
        print 'Errors: {}, Warnings: {}'.format(
            len(self.errors),
            len(self.warnings))
