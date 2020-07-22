# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

"""Forseti CLI helper class"""

import re
import subprocess


class ForsetiCli:
    """Forseti CLI helper

    Run common commands with the Forseti CLI.
    """

    @staticmethod
    def config_show():
        cmd = ['forseti', 'config', 'show']
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_access_by_authz(permission: str = None, role: str = None):
        cmd = ['forseti', 'explainer', 'access_by_authz']
        if permission:
            cmd.extend(['--permission', permission])
        elif role:
            cmd.extend(['--role', role])
        else:
            raise ValueError('Permission or role argument required.')
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_access_by_member(member: str, permissions: list = None):
        cmd = ['forseti', 'explainer', 'access_by_member', member]
        if permissions:
            cmd.extend(permissions)
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_access_by_resource(resource: str):
        cmd = ['forseti', 'explainer', 'access_by_resource', resource]
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_check_policy(resource: str, policy: str, member: str):
        cmd = ['forseti', 'explainer', 'check_policy', resource, policy,
               member]
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_list_members(prefix: str = None):
        cmd = ['forseti', 'explainer', 'list_members']
        if prefix:
            cmd.extend(['--prefix', prefix])
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_list_permissions(roles: list = None,
                                   role_prefixes: list = None):
        cmd = ['forseti', 'explainer', 'list_permissions']
        if roles:
            cmd.append('--roles')
            cmd.extend(roles)
        if role_prefixes:
            cmd.append('--role_prefixes')
            cmd.extend(role_prefixes)
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_list_roles(prefix: str = None):
        cmd = ['forseti', 'explainer', 'list_roles']
        if prefix:
            cmd.extend(['--prefix', prefix])
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_why_denied(member: str, resources: list, roles: list = None,
                             permissions: list = None):
        cmd = ['forseti', 'explainer', 'why_denied', member]
        cmd.extend(resources)
        if permissions:
            cmd.append('--permissions')
            cmd.extend(permissions)
        if roles:
            cmd.append('----roles')
            cmd.extend(roles)
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def explainer_why_granted(member: str, resources: str, role: str = None,
                              permission: str = None):
        cmd = ['forseti', 'explainer', 'why_granted', member, resources]
        if permission:
            cmd.extend(['--permission', permission])
        if role:
            cmd.extend(['--role', role])
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def inventory_create(model_name: str = None):
        cmd = ['forseti', 'inventory', 'create']
        if model_name:
            cmd.extend(['--import_as', model_name])
        result = ForsetiCli.run_process(cmd)
        regex = re.compile('id": "([0-9]*)"')
        match = regex.search(str(result.stdout))
        if match:
            return match.group(1), result
        return '', result

    @staticmethod
    def inventory_delete(inventory_id: str):
        cmd = ['forseti', 'inventory', 'delete', inventory_id]
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def model_create(inventory_id: str, model_name: str):
        cmd = ['forseti', 'model', 'create', '--inventory_index_id',
               inventory_id, model_name]
        result = ForsetiCli.run_process(cmd)
        regex = re.compile('handle": "([a-z0-9]*)"')
        match = regex.search(str(result.stdout))
        if match:
            return match.group(1), result
        return '', result

    @staticmethod
    def model_delete(model_name: str):
        cmd = ['forseti', 'model', 'delete', model_name]
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def model_use(model_name: str):
        cmd = ['forseti', 'model', 'use', model_name]
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def notifier_run(inventory_id: str = None):
        cmd = ['forseti', 'scanner', 'run']
        if inventory_id:
            cmd.extend(['--inventory_index_id', inventory_id])
        return ForsetiCli.run_process(cmd)

    @staticmethod
    def run_process(cmd):
        print(f'Running Forseti command: {" ".join(cmd)}')
        return subprocess.run(cmd, stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)

    @staticmethod
    def scanner_run():
        cmd = ['forseti', 'scanner', 'run']
        result = ForsetiCli.run_process(cmd)
        regex = re.compile('ID: ([0-9]*)')
        match = regex.search(str(result.stdout))
        if match:
            return match.group(1), result
        return '', result
