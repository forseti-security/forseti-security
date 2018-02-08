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

""" File utility functions"""

from __future__ import print_function
import os

from constants import (
    ROOT_DIR_PATH, INPUT_DEPLOYMENT_TEMPLATE_FILENAME,
    INPUT_CONFIGURATION_TEMPLATE_FILENAME)
from utils import print_banner, run_command, sanitize_conf_values


def generate_deployment_templates(template_type, values, datetimestamp):
    """Generate deployment templates.

    Args:
        template_type (str): Type of the template, either cli or server
        values (dict): Values needed for deployment
        datetimestamp (str): Timestamp

    Returns:
        str: Path of the deployment template

    Raises:
        KeyError: KeyError
    """

    template_type = template_type.lower()

    if template_type not in INPUT_DEPLOYMENT_TEMPLATE_FILENAME:
        raise KeyError # template type not found

    input_template_filename = INPUT_DEPLOYMENT_TEMPLATE_FILENAME[template_type]

    # Deployment template in file
    deploy_tpl_path = os.path.abspath(
        os.path.join(
            ROOT_DIR_PATH,
            'deployment-templates',
            input_template_filename))

    out_tpl_path = os.path.abspath(
        os.path.join(
            ROOT_DIR_PATH,
            'deployment-templates',
            'deploy-forseti-{}-{}.yaml'.format(template_type, datetimestamp)))

    if generate_file_from_template(deploy_tpl_path,
                                   out_tpl_path,
                                   values):
        return out_tpl_path

    # Deployment template not generated successfully
    return None


def generate_forseti_conf(template_type, vals, datetimestamp):
    """Generate Forseti conf file.

    Args:
        template_type (str): Type of the template, either cli or server
        vals (dict): Values needed for deployment
        datetimestamp (str): Timestamp

    Returns:
        str: Path of the deployment template

    Raises:
        KeyError: KeyError
    """

    template_type = template_type.lower()

    if template_type not in INPUT_CONFIGURATION_TEMPLATE_FILENAME:
        raise KeyError # template type not found

    input_template_name = INPUT_CONFIGURATION_TEMPLATE_FILENAME[template_type]

    forseti_conf_in = os.path.abspath(
        os.path.join(
            ROOT_DIR_PATH, 'configs', template_type, input_template_name))
    forseti_conf_gen = os.path.abspath(
        os.path.join(
            ROOT_DIR_PATH, 'configs', template_type,
            'forseti_conf_{}_{}.yaml'.format(template_type, datetimestamp)))

    conf_values = sanitize_conf_values(vals)

    if generate_file_from_template(forseti_conf_in,
                                   forseti_conf_gen,
                                   conf_values):
        return forseti_conf_gen

    # forseti_conf not generated successfully
    return None


def generate_file_from_template(template_path, output_path, template_values):
    """Write to file.

    Args:
        template_path (str): Input template path
        output_path (str): Path of the output file
        template_values (dict): Values to replace the
                                ones in the input template
    Returns:
        bool: Whether or not file has been generated
    """

    try:
        with open(template_path, 'r') as in_tmpl:
            tmpl_contents = in_tmpl.read()
            out_contents = tmpl_contents.format(**template_values)
            with open(output_path, 'w') as out_file:
                out_file.write(out_contents)
                return True
    except EnvironmentError:
        pass
    return False


def copy_file_to_destination(file_path, output_path,
                             is_directory, dry_run):
    """Copy the config to the created bucket.

    Args:
        file_path (str): Path to the file
        output_path (str): Path of the copied file
        is_directory (bool): Whether or not the input file_path is a directory
        dry_run (bool): Whether or not the installer is in dry run mode

    Returns:
        bool: True if copy file succeeded, otherwise False.
    """

    print_banner('Copying {} to {}'.format(file_path, output_path))

    if dry_run:
        print('This is a dry run, so skipping this step.')
        return False

    if is_directory:
        args = ['gsutil', 'cp', '-r', file_path, output_path]
    else:
        args = ['gsutil', 'cp', file_path, output_path]

    return_code, out, err = run_command(args)
    if return_code:
        print(err)
    else:
        print(out)
        return True
    return False
