#!/usr/bin/env python
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

"""Setup script for Forseti Security tools."""

import os
import subprocess
import sys

import google.cloud.security

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install

from google.cloud.security import FORSETI_SECURITY_HOME_ENV_VAR


FORSETI_VERSION = google.cloud.security.__version__

NAMESPACE_PACKAGES = [
    'google',
    'google.cloud',
    'google.cloud.security'
]

INSTALL_REQUIRES = [
    'google-api-python-client==1.6.1',
    'MySQL-python==1.2.5',
    'protobuf==3.2.0',
    'PyYAML==3.12',
    'ratelimiter==1.1.0',
    'retrying==1.3.3',
]

SETUP_REQUIRES = [
    'google-apputils==0.4.2',
    'python-gflags==3.1.1',
]

TEST_REQUIRES = [
    'mock==2.0.0',
]

if sys.version_info < (2, 7):
    sys.exit('Sorry, Python < 2.7 is not supported.')

if sys.version_info.major > 2:
    sys.exit('Sorry, Python 3 is not supported.')

def build_protos():
    """Build protos."""
    subprocess.check_call(['python', 'makefile.py', '--clean'])

def set_venv_env_vars():
    """Set environment variables in virtualenv postactivate."""
    cwd = os.path.abspath(os.path.dirname(__file__))
    venv_path = os.environ.get('VIRTUAL_ENV')
    if venv_path:
        # Check if postactivate already has the env vars
        postactivate_script = os.path.join(venv_path, 'bin', 'postactivate')
        p = subprocess.Popen(['grep', FORSETI_SECURITY_HOME_ENV_VAR,
                              postactivate_script],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if not out:
            lines = 'export {}={}'.format(FORSETI_SECURITY_HOME_ENV_VAR, cwd)
            with open(postactivate_script, 'a') as venv_script:
                venv_script.write(lines)
            print ('\n\n*** Run the following line to set your '
                   'environment variable:\n\n'
                   'export {}={}\n\n'.format(
                       FORSETI_SECURITY_HOME_ENV_VAR, cwd))
    else:
        print ('\nNot in a virtualenv. You need to set the {} '
               'environment variable in order to run the '
               'Forseti Security tools.\n\n'
               '{}={}'.format(
                   FORSETI_SECURITY_HOME_ENV_VAR,
                   FORSETI_SECURITY_HOME_ENV_VAR,
                   cwd))

class PostInstallCommand(install):
    """Post installation command."""

    def run(self):
        install.do_egg_install(self)
        build_protos()
        set_venv_env_vars()


setup(
    name='forseti-security',
    version=FORSETI_VERSION,
    description='Forseti Security tools',
    author='Google Inc.',
    author_email='opensource@google.com',
    url='https://github.com/GoogleCloudPlatform/forseti-security',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License'
    ],
    cmdclass={
        'install': PostInstallCommand
    },
    install_requires=SETUP_REQUIRES + INSTALL_REQUIRES,
    setup_requires=SETUP_REQUIRES,
    tests_require=INSTALL_REQUIRES + SETUP_REQUIRES + TEST_REQUIRES,
    packages=find_packages(exclude=[
        '*.tests', '*.tests.*', 'tests.*', 'tests']),
    namespace_packages=NAMESPACE_PACKAGES,
    license='Apache 2.0',
    keywords='gcp google cloud platform security tools',
    entry_points={
        'console_scripts': [
            'forseti_inventory = google.cloud.security.stubs:RunForsetiInventory',
            'forseti_scanner = google.cloud.security.stubs:RunForsetiScanner',
            'forseti_enforcer = google.cloud.security.stubs:RunForsetiEnforcer',
        ]
    }
)
