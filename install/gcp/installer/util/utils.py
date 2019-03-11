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

import os
import re
import sys
import subprocess
import threading
import time

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


def print_banner(*args):
    """Print a banner.

    Args:
        args (str): Text(s) to put in the banner.
    """
    texts = [arg for arg in args]
    _print_banner(border_symbol='-',
                  edge_symbol='|',
                  corner_symbol='+',
                  length=80,
                  wrap_border=False,
                  texts=texts)


def print_installation_header(*args):
    """Print installation header.

    Installation header will have a different pattern than a normal banner.

    Args:
        args (str): Text(s) to put in the banner.
    """
    texts = [arg for arg in args]
    _print_banner(border_symbol='#',
                  edge_symbol='#',
                  corner_symbol='#',
                  length=80,
                  wrap_border=True,
                  texts=texts)


def _print_banner(border_symbol, edge_symbol, corner_symbol,
                  length, wrap_border, texts):
    """Print a banner.

    Args:
        border_symbol (str): The symbol used on the border.
        edge_symbol (str): The symbol used on the edge.
        corner_symbol (str): The symbol to put at the corners.
        length (int): The length of the border.
        wrap_border (bool): Whether or not we want to wrap around the border.
        texts (list): Text(s) to put in the banner.
    """
    if wrap_border:
        border = corner_symbol + border_symbol * (length - 2) + corner_symbol
    else:
        border = corner_symbol + border_symbol * (length - 1)

    print('')
    print(border)
    for text in texts:
        text = '  ' + text
        if wrap_border:
            # Pad the text with empty space
            padded_text = text + ' ' * (length - len(text) - 2)
            print(edge_symbol + padded_text + edge_symbol)
        else:
            print(edge_symbol + text)
    print(border)
    print('')


def get_forseti_version():
    """Get the current Forseti version.

    If the current version is a branch or a tag, we will return it. Otherwise
    we will read the __init__ file for the latest version.

    Returns:
        str: The version, that is either a tag or a branch name.
    """
    version = None

    # Check version by tag.
    return_code, out, _ = run_command(
        ['git', 'describe', '--tags', '--exact-match'],
        number_of_retry=0,
        suppress_output=True)
    # The git command above will return the tag name if we checked out
    # a tag, will throw an exception otherwise.
    if not return_code:
        return 'tags/{}'.format(out.strip())

    # Check version by branch. Allow installs from development branches.
    return_code, out, err = run_command(
        ['git', 'symbolic-ref', '-q', '--short', 'HEAD'],
        number_of_retry=0)
    # The git command above will return empty if the user is not currently
    # on a branch.
    if return_code:
        print(err)
    else:
        version = out.strip()

    # If there is a version and it's not branch `stable`, we don't need to
    # read the __init__.py file for version.
    if version and version != 'stable':
        return version

    # Check version by source code.
    # Installing from stable branch must be pinned to a release tag.
    version_re = re.compile(constants.VERSIONFILE_REGEX)
    version_file = os.path.join(
        constants.FORSETI_SRC_PATH, '__init__.py')
    with open(version_file, 'rt') as vfile:
        for line in vfile:
            version_match = version_re.match(line)
            if version_match:
                version = 'tags/v%s' % version_match.group(1)
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


def generate_service_acct_info(prefix, installation_type,
                               timestamp, project_id):
    """Format the service account email and name.

    Args:
        prefix (str): The prefix of the account id and account name.
        installation_type (str): Type of the installation (client/server).
        timestamp (str): The timestamp.
        project_id (str): Id of the project on GCP.

    Returns:
        str: Service account email.
        str: Service account name.
    """

    service_account_name = constants.SERVICE_ACCT_NAME_FMT.format(
        installation_type, prefix, timestamp)

    service_account_email = full_service_acct_email(service_account_name,
                                                    project_id)

    return service_account_email, service_account_name


def infer_version():
    """Infer the Forseti version, or ask user to input one not listed.

    Returns:
        str: Selected Forseti branch.
    """

    cur_version = get_forseti_version()

    if not cur_version:
        print('Unable to determine the current Forseti version, please check '
              'https://forsetisecurity.org/docs/latest/faq/'
              '#installation-and-deployment for more information.')
        sys.exit(1)

    return cur_version


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


def run_command(cmd_args, number_of_retry=5,
                timeout_in_second=90, suppress_output=False):
    """Wrapper to run a command in subprocess.

    If there is a timeout/error on the API call, we will re try up to 5 times
    by default.
    Each re try will increment timeout_in_second by 10.

    Args:
        cmd_args (list): The list of command arguments.
        number_of_retry (int): Number of re try.
        timeout_in_second (int): Timeout in second.
        suppress_output (bool): Suppress output.

    Returns:
        int: The return code. 0 is "ok", anything else is "error".
        str: Output, if command was successful.
        err: Error output, if there was an error.
    """
    proc = subprocess.Popen(cmd_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    timer = threading.Timer(timeout_in_second, proc.kill)

    timer.start()
    out, err = proc.communicate()
    timer.cancel()

    if proc.returncode and number_of_retry >= 1:
        if not suppress_output:
            print('Command "{}" failed/timeout, retrying...'.format(
                ' '.join(cmd_args)))
        return run_command(cmd_args,
                           number_of_retry - 1,
                           timeout_in_second + 10,
                           suppress_output=suppress_output)

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


def start_loading(max_loading_time, exit_condition_checker=None,
                  message='', max_number_of_dots=15):
    """Start and show the loading message, append dots to the end
    of the message up to a certain number of dots and repeat.

    Args:
        max_loading_time (int): Loading time in seconds.
        exit_condition_checker (func): Exit condition checker, a function that
         returns boolean, will be called every second to check for the return
         result.
        message (str): Message to print to stdout.
        max_number_of_dots (int): Maximum number of dots on the line.

    Returns:
        bool: Status of the loading.
    """

    # VT100 control codes, use to remove the last line.
    erase_line = '\x1b[2K'

    for i in range(0, max_loading_time*2):
        if exit_condition_checker and exit_condition_checker():
            print('done\n')
            return True
        # Sleep for 0.5 second so that the dots can appear more quickly
        # to be more user friendly.
        time.sleep(0.5)
        dots = '.' * (i % max_number_of_dots)
        sys.stdout.write('\r{}{}{} '.format(erase_line, message, dots))
        sys.stdout.flush()
    print ('time limit reached')
    return False
