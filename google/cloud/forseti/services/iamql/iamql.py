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

""" IAMQL API. """


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc,invalid-name

from google.cloud.security.iam.iamql.langspec import BNF


class IamQL(object):
    """Implements the IAMQL API."""

    def __init__(self, config):
        self.config = config

    def Query(self, model_name, query):
        """Implement the general query functionality."""

        raise NotImplementedError()

    def QueryString(self, model_name, query):
        """Implement the general query functionality."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            bnf = BNF()
            results = bnf.parseString(query, parseAll=True)
            print results.dump()
            return data_access.iamql_query(session, query)
