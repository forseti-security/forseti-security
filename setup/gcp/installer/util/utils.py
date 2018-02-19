# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utils.

This has been tested with python 2.7.
"""

from __future__ import print_function

import subprocess
import re
import os

import constants


def id_from_name(name):
    """Extract the id from the resource name.

    Args:
        name (str): The name of the resource, formatted as
            "${RESOURCE_TYPE}/${RESOURCE_ID}".

    Returns:
        str: The resource id.
    """
    if not name or not '/' in name:
        return name
    return name[name.index('/')+1:]


def print_banner(text):
    """Print a banner.

    Args:
        text (str): Text to put in the banner.
    """
    print('')
    print('+-------------------------------------------------------')
    print('|  %s' % text)
    print('+-------------------------------------------------------')
    print('')


def get_forseti_version():
    """Get Forseti version from version file.

    Returns:
        str: The version.
    """
    version = None
    version_re = re.compile(constants.VERSIONFILE_REGEX)
    version_file = os.path.join(
        constants.FORSETI_SRC_PATH, '__init__.py')
    with open(version_file, 'rt') as vfile:
        for line in vfile:
            version_match = version_re.match(line)
            if version_match:
                version = version_match.group(1)
                break
    return version


def get_remote_branches():
    """Get remote git branches.

    Returns:
        list: A list of branches.
    """
    branches = []
    return_code, out, err = run_command(
        ['git', 'branch', '-r'])
    if return_code:
        print(err)
    else:
        out = out.strip()
        if out:
            branches = [b.strip() for b in out.split('\n')]
    return branches


def checkout_git_branch():
    """Let user choose git branch and check it out.

    Returns:
        str: The checked out branch, if exists.
    """
    branches = get_remote_branches()
    choice_index = -1
    while choice_index < 0 or choice_index > len(branches):
        branches = get_remote_branches()
        print('Remote branches:')
        for (i, branch) in enumerate(branches):
            print('[%s] %s' % (i+1, branch[len('origin/'):]))
        try:
            choice_index = int(raw_input(
                'Enter your numerical choice: ').strip())
        except ValueError:
            print('Invalid input choice, try again.')
    branch = branches[choice_index-1][len('origin/'):]
    return_code, _, err = run_command(
        ['git', 'checkout', branch])
    if return_code:
        print(err)
    return branch


def full_service_acct_email(account_id, project_id):
    """Generate the full service account email.

    Args:
        account_id (str): The service account id, i.e. the part before
            the "@".
        project_id (str): The project id the service account belongs to

    Returns:
        str: The full service account email.
    """
    return constants.SERVICE_ACCT_EMAIL_FMT.format(
        account_id, project_id)


def format_resource_id(resource_type, resource_id):
    """Format the resource id as $RESOURCE_TYPE/$RESOURCE_ID.

    Args:
        resource_type (str): The resource type.
        resource_id (str): The resource id.

    Returns:
        str: The formatted resource id.
    """
    return '%s/%s' % (resource_type, resource_id)


def format_service_acct_id(prefix, modifier, timestamp, project_id):
    """Format the service account ids.

    Args:
        prefix (str): The prefix of the account id
        modifier (str): Access level of the account
        timestamp (str): Timestamp of the class
        project_id (str): Id of the project on GCP

    Returns:
        str: Service account id
    """

    return full_service_acct_email(
        constants.SERVICE_ACCT_FMT.format(
            prefix, modifier, timestamp), project_id)


def infer_version(advanced_mode):
    """Infer the Forseti version, or ask user to input one not listed.

    Args:
        advanced_mode (bool): Whether or not the installer is in advanced mode

    Returns:
        str: Selected Forseti branch
    """
    return_code, out, err = run_command(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    if return_code:
        print(err)
        print('Will try to infer the Forseti version instead.')
    else:
        branch = out.strip()

    user_choice = None
    if not branch or branch == 'master':
        version = get_forseti_version()
        if version:
            branch = 'v%s' % version

    if not advanced_mode:
        user_choice = 'y'

    while user_choice != 'y' and user_choice != 'n':
        user_choice = raw_input(
            'Install Forseti branch/tag %s? (y/n) '
            % branch).lower().strip()

    if user_choice == 'n':
        branch = checkout_git_branch()
        if branch:
            branch = branch
        else:
            print('No branch was chosen; using %s' % branch)

    print('Forseti branch/tag: %s' % branch)
    return branch


def get_zone_from_bucket_location(bucket_location):
    """Get zone from bucket location.

    Args:
        bucket_location (str): Bucket location

    Returns:
        str: Zone for that given bucket location
    """

    return '{}-c'.format(bucket_location)


def get_choice_id(choices, print_function):
    """Get choice id from user.

    Args:
        choices (list): A list of choices
        print_function (method): Print function
    Returns:
        int: choice id
    """
    while True:
        for (i, choice) in enumerate(choices):
            print_function(i, choice)

        choice_input = raw_input(
            'Enter the number of your choice: ').strip()

        try:
            choice_index = int(choice_input)
            if choice_index < 1 or choice_index > len(choices):
                raise ValueError
            else:
                break
        except ValueError:
            print('Invalid choice "%s", try again' % choice_input)
    return choice_index


def extract_timestamp_from_name(instance_name, include_date=False):
    """Extract timestamp from instance name.

    Example instance_name: forseti-security-server-20180207125916-vm
    Example output: '125916' if include_date is false,
                    '20180207125916' otherwise
    Args:
        instance_name (str): Name of the instance
        include_date (bool): Include date in the timestamp

    Returns:
        str: Timestamp
    """
    if instance_name is None:
        return ''

    if include_date:
        return instance_name.split('-')[-2]
    return instance_name.split('-')[-2][8:]


def run_command(cmd_args):
    """Wrapper to run a command in subprocess.

    Args:
        cmd_args (list): The list of command arguments.

    Returns:
        int: The return code. 0 is "ok", anything else is "error".
        str: Output, if command was successful.
        err: Error output, if there was an error.
    """
    proc = subprocess.Popen(cmd_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return proc.returncode, out, err


def sanitize_conf_values(conf_values):
    """Sanitize the forseti_conf values not to be zero-length strings.

    Args:
        conf_values (dict): The conf values to replace in the
            forseti_conf_server.yaml.

    Returns:
        dict: The sanitized values.
    """
    for key in conf_values.keys():
        if not conf_values[key]:
            conf_values[key] = '""'
    return conf_values


def merge_dict(base_dict, target_dict,
               fields_to_ignore=None, field_identifiers=None):
    """Merge target_dict into base_dict.

    Note: base_dict will be modified during the merge process

    Args:
        base_dict (dict): Base dictionary.
        target_dict (dict): Target dictionary.
        fields_to_ignore (list): Fields to ignore (keep in base_dict)
        field_identifiers (dict): Identifiers for fields
    """
    # Init default values for fields_to_ignore and field_identifiers
    # if they don't already exists
    if fields_to_ignore is None:
        fields_to_ignore = []
    if field_identifiers is None:
        field_identifiers = {}

    for key, val in base_dict.iteritems():
        # print (key + "      ///////        " + str(val))
        if key in target_dict:
            # If target_dict has the same key, we check if the value is
            # an instance of dictionary. If it is we merge recursively and
            # if it's not, we do a simple replace if the key is not in
            # fields_to_ignore
            if key in fields_to_ignore:
                continue
            if isinstance(val, dict):
                merge_dict(val, target_dict.get(key),
                           fields_to_ignore, field_identifiers)
            elif isinstance(val, list) and val:
                # If the list has at least one item, we check for the type
                # of the first item, if it's a dictionary, we invoke
                # merge_dict_list, otherwise we will do a simple merge of
                # 2 lists
                if isinstance(val[0], dict):
                    identifier = field_identifiers.get(key)
                    merge_dict_list(val, target_dict.get(key), identifier,
                                    fields_to_ignore, field_identifiers)
                else:
                    # Cast the merged list to a set to remove duplicate
                    # and cast it back to a list afterward
                    base_dict[key] = list(set(val + target_dict.get(key)))
            else:
                base_dict[key] = target_dict.get(key)

    for key, val in target_dict.iteritems():
        if key not in base_dict and key not in fields_to_ignore:
            # If this is a key we have only in target but not in base, we add
            # it to the base_dict
            base_dict[key] = val


def merge_dict_list(base_dict_list, target_dict_list, identifier,
                    fields_to_ignore, field_identifiers):
    """Merge target_dict_list into base_dict_list.

    Note: base_dict_list will be modified during the merge process.

    Args:
        base_dict_list (list): Base dictionary.
        target_dict_list (list): Target dictionary.
        identifier (str): Current field identifier.
        fields_to_ignore (list): Fields to ignore (keep in base_dict).
        field_identifiers (dict): Identifiers for fields.
    """

    # Sort both base_dict_list and target_dict_list by the identifier
    base_dict_list.sort(key=lambda k: k[identifier])
    target_dict_list.sort(key=lambda k: k[identifier])

    # Merge them
    base_counter = 0
    target_counter = 0
    max_items = max(len(base_dict_list), len(target_dict_list))
    for _ in range(0, max_items):
        cur_base_dict = (None if len(base_dict_list) <= base_counter
                         else base_dict_list[base_counter])
        cur_taget_dict = (None if len(target_dict_list) <= target_counter
                          else target_dict_list[target_counter])

        if target_counter >= len(target_dict_list):
            break
        elif (base_counter >= len(base_dict_list) or
              cur_base_dict[identifier] > cur_taget_dict[identifier]):
            # cur_target_object only exists in target_dict_list,
            # add it to base_dict_list, increment target_counter
            base_dict_list.append(cur_taget_dict)
            target_counter += 1
        elif cur_base_dict[identifier] < cur_taget_dict[identifier]:
            # cur_base_dict object only exists in base_dict_list,
            # increment base_counter
            base_counter += 1
        else:
            # They have the same identifier, merge them,
            # increment both counters
            merge_dict(cur_base_dict, cur_taget_dict,
                       fields_to_ignore, field_identifiers)
            base_counter += 1
            target_counter += 1
