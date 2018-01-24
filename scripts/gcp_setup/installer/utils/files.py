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

from constants import ROOT_DIR_PATH, INPUT_DEPLOYMENT_TEMPLATE_FILENAME,\
    INPUT_CONFIGURATION_TEMPLATE_FILENAME
from utils import print_banner, run_command


def generate_deployment_templates(template_type, vals, datetimestamp):
    """Generate deployment templates.

    Args:
        template_type (str): Type of the template, either cli or server
        vals (dict): Values needed for deployment
        datetimestamp (str): Timestamp

    Returns:
        str: Path of the deployment template

    Raise:
        KeyError
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

    # Create Deployment template with values filled in.
    with open(deploy_tpl_path, 'r') as in_tmpl:
        tmpl_contents = in_tmpl.read()
        out_contents = tmpl_contents.format(**vals)
        with open(out_tpl_path, 'w') as out_tmpl:
            out_tmpl.write(out_contents)
            return out_tpl_path


def generate_forseti_conf(template_type, vals, datetimestamp):
    """Generate Forseti conf file.

    Args:
        template_type (str): Type of the template, either cli or server
        vals (dict): Values needed for deployment
        datetimestamp (str): Timestamp

    Returns:
        str: Path of the deployment template

    Raise:
        KeyError
    """

    template_type = template_type.lower()

    if template_type not in INPUT_CONFIGURATION_TEMPLATE_FILENAME:
        raise KeyError # template type not found

    input_template_name = INPUT_CONFIGURATION_TEMPLATE_FILENAME[template_type]

    forseti_conf_in = os.path.abspath(
        os.path.join(
            ROOT_DIR_PATH, 'configs', input_template_name))
    forseti_conf_gen = os.path.abspath(
        os.path.join(
            ROOT_DIR_PATH, 'configs',
            'forseti_conf_{}_{}.yaml'.format(template_type, datetimestamp)))

    conf_values = sanitize_conf_values(vals)

    with open(forseti_conf_in, 'rt') as in_tmpl:
        tmpl_contents = in_tmpl.read()
        out_contents = tmpl_contents.format(**conf_values)
        with open(forseti_conf_gen, 'w') as out_tmpl:
            out_tmpl.write(out_contents)
            return forseti_conf_gen


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
        return False, False

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


def sanitize_conf_values(conf_values):
    """Sanitize the forseti_conf values not to be zero-length strings.

    Args:
        conf_values (dict): The conf values to replace in the
            forseti_conf.yaml.

    Returns:
        dict: The sanitized values.
    """
    for key in conf_values.keys():
        if not conf_values[key]:
            conf_values[key] = '""'
    return conf_values
