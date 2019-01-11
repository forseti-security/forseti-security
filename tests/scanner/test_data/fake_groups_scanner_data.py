# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from MySQLdb.constants.REFRESH import STATUS

"""Test data for groups scanner tests.

Example data setup.
group: aaaaa@mycompany.com
  member: adam@mycompany.com
  member: abby@mycompany.com
  member: amelia@gmail.com

group: bbbbb@mycompany.com
  member: bob@mycompany.com
  member: beth@mycompany.com
  member: ccccc@mycompany.com

group: ccccc@mycompany.com
  member: charlie@mycompany.com
  member: cassy@mycompany.com
  member: chrisy@gmail.com

group: ddddd@mycompany.com
  member: david@mycompany.com
  member: daisy@mycompany.com
  member: bbbbb@mycompany.com
"""

class FakeGroup:
    def __init__(self, name, member_name, type):
        self.name = name
        self.member_name = member_name
        self.type = type


ALL_GROUPS = (
    FakeGroup('aaaaa', 'aaaaa@mycompany.com', 'admin#directory#group'),
    FakeGroup('bbbbb', 'bbbbb@mycompany.com', 'admin#directory#group'),
    FakeGroup('ccccc', 'ccccc@mycompany.com', 'admin#directory#group'),
    FakeGroup('ddddd', 'ddddd@mycompany.com', 'admin#directory#group'),
)


class FakeMember:
    def __init__(self, name, member_name, type, starting_node):
        self.name = name
        self.member_name = member_name
        self.type = type
        self.starting_node = starting_node


AAAAA_GROUP_MEMBERS = [
    FakeMember('adam', 'adam@mycompany.com', 'USER', 'aaaaa'),
    FakeMember('abby', 'abby@mycompany.com', 'USER', 'aaaaa'),
    FakeMember('amelia', 'amelia@mycompany.com', 'USER', 'aaaaa'),
]

CCCCC_GROUP_MEMBERS = [
    FakeMember('charlie', 'charlie@mycompany.com', 'USER', 'ccccc'),
    FakeMember('cassy', 'cassy@mycompany.com', 'USER', 'ccccc'),
    FakeMember('christy', 'christy@yahoo.com', 'USER', 'ccccc'),
]

BBBBB_GROUP_MEMBERS = [
    FakeMember('bob', 'bob@mycompany.com', 'USER', 'bbbbb'),
    FakeMember('beth', 'beth@mycompany.com', 'USER', 'bbbbb'),
]
BBBBB_GROUP_MEMBERS += CCCCC_GROUP_MEMBERS

DDDDD_GROUP_MEMBERS = [
    FakeMember('david', 'david@mycompany.com', 'USER', 'ddddd'),
    FakeMember('daisy', 'daisy@mycompany.com', 'USER', 'ddddd'),
]
DDDDD_GROUP_MEMBERS += BBBBB_GROUP_MEMBERS

# The order of these groups will be determined by the nesting structure
# and by how the get_recursive_members() will return them.
ALL_GROUP_MEMBERS = [
    AAAAA_GROUP_MEMBERS,
    BBBBB_GROUP_MEMBERS,
    CCCCC_GROUP_MEMBERS,
    DDDDD_GROUP_MEMBERS,
]

EXPECTED_MEMBERS_IN_TREE = (
'''"my_customer"
|-- "aaaaa@mycompany.com"
|   |-- "adam@mycompany.com"
|   |-- "abby@mycompany.com"
|   +-- "amelia@mycompany.com"
|-- "bbbbb@mycompany.com"
|   |-- "bob@mycompany.com"
|   |-- "beth@mycompany.com"
|   |-- "charlie@mycompany.com"
|   |-- "cassy@mycompany.com"
|   +-- "christy@yahoo.com"
|-- "ccccc@mycompany.com"
|   |-- "charlie@mycompany.com"
|   |-- "cassy@mycompany.com"
|   +-- "christy@yahoo.com"
+-- "ddddd@mycompany.com"
    |-- "david@mycompany.com"
    |-- "daisy@mycompany.com"
    |-- "bob@mycompany.com"
    |-- "beth@mycompany.com"
    |-- "charlie@mycompany.com"
    |-- "cassy@mycompany.com"
    +-- "christy@yahoo.com"'''
)

EXPECTED_RULES_IN_TREE = (
"""{"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   {"conditions": [{"member_email": "@gmail.com"}], "group_email": "aaaaa@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in AAAAA group."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |   {"conditions": [{"member_email": "@gmail.com"}], "group_email": "aaaaa@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in AAAAA group."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |   {"conditions": [{"member_email": "@gmail.com"}], "group_email": "aaaaa@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in AAAAA group."}
|   +-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|       {"conditions": [{"member_email": "@gmail.com"}], "group_email": "aaaaa@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in AAAAA group."}
|-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   +-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   {"conditions": [{"member_email": "@gmail.com"}], "group_email": "ccccc@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in CCCCC group."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |   {"conditions": [{"member_email": "@gmail.com"}], "group_email": "ccccc@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in CCCCC group."}
|   |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|   |   {"conditions": [{"member_email": "@gmail.com"}], "group_email": "ccccc@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in CCCCC group."}
|   +-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
|       {"conditions": [{"member_email": "@gmail.com"}], "group_email": "ccccc@mycompany.com", "mode": "whitelist", "name": "Allow gmail users to be in CCCCC group."}
+-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    |-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}
    +-- {"conditions": [{"member_email": "@mycompany.com"}], "group_email": "my_customer", "mode": "whitelist", "name": "Allow my company users to be in my company groups."}""")
