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

"""IAMQL data model translations"""

from sqlalchemy import and_


class Metadata(object):
    """Data model metadata used to query and join between entities."""

    """Description of attributes and types for each entity."""
    entity_attributes = {
        'resource': {
            'path': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            'name': {
                'type': unicode,
                },
            'display_name': {
                'type': unicode,
                },
            'email': {
                'type': unicode,
                },
            },
        'role': {
            'name': {
                'type': unicode,
                },
            'title': {
                'type': unicode,
                },
            'description': {
                'type': unicode,
                },
            },
        'permission': {
            'name': {
                'type': unicode,
                },
            },
        'member': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'group': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'user': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'serviceaccount': {
            'name': {
                'type': unicode,
                },
            'type': {
                'type': unicode,
                },
            },
        'binding': {},
        }

    """Relation definitions between entities.
    Relations are in the form var.$relation(var, ...)"""
    allowed_joins = {
        'group': [
            ('contains',
             [['group', 'member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_MEMBERSHIP.c.group_name == parent.table.name,
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             [['member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.name,
                  (dao.TBL_GROUP_IN_GROUP.member ==
                   dao.TBL_MEMBERSHIP.c.group_name),
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             ['group'],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.member,
                  dao.TBL_GROUP_IN_GROUP.member == child.table.member),
                 )),
            ],
        'member': [
            ('contains',
             [['group', 'member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_MEMBERSHIP.c.group_name == parent.table.name,
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             [['member', 'user', 'serviceaccount']],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.name,
                  (dao.TBL_GROUP_IN_GROUP.member ==
                   dao.TBL_MEMBERSHIP.c.group_name),
                  dao.TBL_MEMBERSHIP.c.members_name == child.table.name)
                 )),
            ('transitivecontains',
             ['group'],
             lambda dao, parent, child: (
                 and_(
                  dao.TBL_GROUP_IN_GROUP.parent == parent.table.member,
                  dao.TBL_GROUP_IN_GROUP.member == child.table.member),
                 )),
            ],
        'role': [
            ('has',
             ['permission'],
             lambda dao, r, p: (
                 and_(
                    dao.TBL_ROLE_PERMISSION.c.roles_name == r.table.name,
                    dao.TBL_ROLE_PERMISSION.c.permissions_name == p.table.name)
                 )),
            ],
        'binding': [
            ('grants',
             ['resource', 'role', ['member',
                                   'user',
                                   'group',
                                   'serviceaccount']],
             lambda dao, binding, resource, role, member: (
                 and_(
                  binding.table.resource_type_name == resource.table.type_name,
                  binding.table.role_name == role.table.name,
                  dao.TBL_BINDING_MEMBERS.c.members_name == member.table.name,
                  dao.TBL_BINDING_MEMBERS.c.bindings_id == binding.table.id)
                 )),
            ],
        'permission': [
            ('included',
             ['role'],
             lambda dao, p, r: (
                 and_(
                    dao.TBL_ROLE_PERMISSION.c.roles_name == r.table.name,
                    dao.TBL_ROLE_PERMISSION.c.permissions_name == p.table.name)
                 )),
            ],
        'resource': [
            ('child',
             ['resource'],
             lambda dao, child, parent: (
                 and_(child.table.parent_type_name == parent.table.type_name)
                 )),
            ('parent',
             ['resource'],
             lambda dao, parent, child: (
                 and_(child.table.parent_type_name == parent.table.type_name)
                 )),
            ('ancestor',
             ['resource'],
             lambda dao, ancestor, descendant: (
                 and_(
                     descendant.table.full_name.startswith(
                         ancestor.table.full_name),
                     ancestor.table.type_name != descendant.table.type_name)
                 )),
            ('ancestorWithSelf',
             ['resource'],
             lambda dao, ancestor, descendant: (
                 descendant.table.full_name.startswith(
                     ancestor.table.full_name)
                 )),
            ('descendant',
             ['resource'],
             lambda dao, descendant, ancestor: (
                 and_(
                     descendant.table.full_name.startswith(
                         ancestor.table.full_name),
                     ancestor.table.type_name != descendant.table.type_name)
                 )),
            ],
        }

    """Name->Table mapping for entities."""
    type_mapping = {
        'resource': (
            lambda dao: dao.TBL_RESOURCE,
            None),
        'role': (
            lambda dao: dao.TBL_ROLE,
            None),
        'permission': (
            lambda dao: dao.TBL_PERMISSION,
            None),
        'binding': (
            lambda dao: dao.TBL_BINDING,
            None),
        'member': (
            lambda dao: dao.TBL_MEMBER,
            lambda t, dao: t.type.in_(dao.TBL_MEMBER.CORE_TYPES)),
        'group': (
            lambda dao: dao.TBL_MEMBER,
            lambda t, dao: t.type == 'group'),
        'user': (
            lambda dao: dao.TBL_MEMBER,
            lambda t, dao: t.type == 'user'),
        'serviceaccount': (
            lambda dao: dao.TBL_MEMBER,
            lambda t, dao: t.type == 'serviceAccount')
            }
