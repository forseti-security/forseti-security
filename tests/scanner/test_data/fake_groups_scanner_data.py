# Copyright 2017 Google Inc.
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

ALL_GROUPS = (
    {'direct_member_count': 3L,
     'group_email': 'aaaaa@mycompany.com',
     'group_id': 'aaaaa',
     'group_kind': 'admin#directory#group',
     'id': 1L,
    },
    {'direct_member_count': 3L,
     'group_email': 'bbbbb@mycompany.com',
     'group_id': 'bbbbb',
     'group_kind': 'admin#directory#group',
     'id': 2L,
    },
    {'direct_member_count': 3L,
     'group_email': 'ccccc@mycompany.com',
     'group_id': 'ccccc',
     'group_kind': 'admin#directory#group',
     'id': 3L,
    },
    {'direct_member_count': 3L,
     'group_email': 'ddddd@mycompany.com',
     'group_id': 'ddddd',
     'group_kind': 'admin#directory#group',
     'id': 4L,
    },
)

AAAAA_GROUP_MEMBERS = (
    {'group_id': 'aaaaa',
     'member_email': 'adam@mycompany.com',
     'member_id': 'adam',
     'member_role': 'OWNER',
     'member_type': 'USER'},
    {'group_id': 'aaaaa',
     'member_email': 'abby@mycompany.com',
     'member_id': 'adam',
     'member_role': 'MEMBER',
     'member_type': 'USER'},
    {'group_id': 'aaaaa',
     'member_email': 'amelia@gmail.com',
     'member_id': 'amelia',
     'member_role': 'MEMBER',
     'member_type': 'USER'}
)

BBBBB_GROUP_MEMBERS = (
    {'group_id': 'bbbbb',
     'member_email': 'bob@mycompany.com',
     'member_id': 'bob',
     'member_role': 'OWNER',
     'member_type': 'USER'},
    {'group_id': 'bbbbb',
     'member_email': 'beth@mycompany.com',
     'member_id': 'beth',
     'member_role': 'MEMBER',
     'member_type': 'USER'},
    {'group_id': 'bbbbb',
     'member_email': 'ccccc@mycompany.com',
     'member_id': 'ccccc',
     'member_role': 'MEMBER',
     'member_type': 'GROUP'},
)

CCCCC_GROUP_MEMBERS = (
    {'group_id': 'ccccc',
     'member_email': 'charlie@mycompany.com',
     'member_id': 'charlie',
     'member_role': 'OWNER',
     'member_type': 'USER'},
    {'group_id': 'ccccc',
     'member_email': 'cassy@mycompany.com',
     'member_id': 'cassy',
     'member_role': 'MEMBER',
     'member_type': 'USER'},
    {'group_id': 'ccccc',
     'member_email': 'christy@gmail.com',
     'member_id': 'christy',
     'member_role': 'MEMBER',
     'member_type': 'USER'}
)

DDDDD_GROUP_MEMBERS = (
    {'group_id': 'ddddd',
     'member_email': 'david@mycompany.com',
     'member_id': 'david',
     'member_role': 'OWNER',
     'member_type': 'USER'},
    {'group_id': 'ddddd',
     'member_email': 'daisy@mycompany.com',
     'member_id': 'daisy',
     'member_role': 'MEMBER',
     'member_type': 'USER'},
    {'group_id': 'ddddd',
     'member_email': 'bbbbb@mycompany.com',
     'member_id': 'bbbbb',
     'member_role': 'MEMBER',
     'member_type': 'GROUP'}
)

# The order of these groups will be determined by the nesting structure
# and by how the get_recursive_members() will return them.
ALL_GROUP_MEMBERS = [
    AAAAA_GROUP_MEMBERS,
    BBBBB_GROUP_MEMBERS,
    CCCCC_GROUP_MEMBERS,
    CCCCC_GROUP_MEMBERS,
    DDDDD_GROUP_MEMBERS,
    BBBBB_GROUP_MEMBERS,
    CCCCC_GROUP_MEMBERS
]

EXPECTED_MEMBERS_IN_TREE = (
"""my_customer
|-- aaaaa@mycompany.com
|   |-- adam@mycompany.com
|   |-- abby@mycompany.com
|   +-- amelia@gmail.com
|-- bbbbb@mycompany.com
|   |-- bob@mycompany.com
|   |-- beth@mycompany.com
|   +-- ccccc@mycompany.com
|       |-- charlie@mycompany.com
|       |-- cassy@mycompany.com
|       +-- christy@gmail.com
|-- ccccc@mycompany.com
|   |-- charlie@mycompany.com
|   |-- cassy@mycompany.com
|   +-- christy@gmail.com
+-- ddddd@mycompany.com
    |-- david@mycompany.com
    |-- daisy@mycompany.com
    +-- bbbbb@mycompany.com
        |-- bob@mycompany.com
        |-- beth@mycompany.com
        +-- ccccc@mycompany.com
            |-- charlie@mycompany.com
            |-- cassy@mycompany.com
            +-- christy@gmail.com"""
)

EXPECTED_RULES_IN_TREE = (
"""{'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   {'group_email': 'aaaaa@mycompany.com', 'conditions': [{'member_email': '@gmail.com'}], 'mode': 'whitelist', 'name': 'Allow gmail users to be in a group.'}
|   |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   |   {'group_email': 'aaaaa@mycompany.com', 'conditions': [{'member_email': '@gmail.com'}], 'mode': 'whitelist', 'name': 'Allow gmail users to be in a group.'}
|   |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   |   {'group_email': 'aaaaa@mycompany.com', 'conditions': [{'member_email': '@gmail.com'}], 'mode': 'whitelist', 'name': 'Allow gmail users to be in a group.'}
|   +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|       {'group_email': 'aaaaa@mycompany.com', 'conditions': [{'member_email': '@gmail.com'}], 'mode': 'whitelist', 'name': 'Allow gmail users to be in a group.'}
|-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|       |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|       |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|       +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
|   +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
+-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
    |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
    |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
    +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
        |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
        |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
        +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
            |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
            |-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}
            +-- {'group_email': 'my_customer', 'conditions': [{'member_email': '@mycompany.com'}], 'mode': 'whitelist', 'name': 'Allow my company users to be in my company groups.'}"""
)
