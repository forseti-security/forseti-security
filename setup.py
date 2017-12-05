#!/usr/bin/env python
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

"""Setup script for Forseti Security tools."""

import os
import subprocess
import sys

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install

import google.cloud.forseti

FORSETI_VERSION = google.cloud.forseti.__version__

NAMESPACE_PACKAGES = [
    'google',
    'google.cloud',
    'google.cloud.forseti'
]

INSTALL_REQUIRES = [
    'anytree>=2.1.4',
    'futures>=3.0.5',
    'google-api-python-client>=1.6.1',
    'Jinja2>=2.9.5',
    'MySQL-python>=1.2.5',
    'netaddr>=0.7.19',
    'protobuf>=3.2.0',
    'PyYAML>=3.12',
    'ratelimiter>=1.1.0',
    'retrying>=1.3.3',
    'requests[security]>=2.18.4',
    'sendgrid>=3.6.3',
    'SQLAlchemy>=1.1.9',
    'pygraph>=0.2.1',
    'unicodecsv>=0.14.1',
]

SETUP_REQUIRES = [
    'google-apputils>=0.4.2',
    'python-gflags>=3.1.1',
    'grpcio',
    'grpcio-tools',
    'protobuf>=3.2.0',
]

TEST_REQUIRES = [
    'mock>=2.0.0',
    'SQLAlchemy>=1.1.9',
    'parameterized>=0.6.1',
    'simple-crypt>=4.1.7',
]

if sys.version_info < (2, 7):
    sys.exit('Sorry, Python < 2.7 is not supported.')

if sys.version_info.major > 2:
    sys.exit('Sorry, Python 3 is not supported.')


def build_protos():
    """Build protos."""
    subprocess.check_call(['python', 'build_protos.py', '--clean'])


class PostInstallCommand(install):
    """Post installation command."""

    def run(self):
        build_protos()
        install.do_egg_install(self)


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
        'install': PostInstallCommand,
    },
    install_requires=SETUP_REQUIRES + INSTALL_REQUIRES,
    setup_requires=SETUP_REQUIRES,
    tests_require=INSTALL_REQUIRES + SETUP_REQUIRES + TEST_REQUIRES,
    packages=find_packages(exclude=[
        '*.tests', '*.tests.*', 'tests.*', 'tests']),
    include_package_data=True,
    package_data={
        '': ['cloud/security/common/email_templates/*.jinja']
    },
    namespace_packages=NAMESPACE_PACKAGES,
    google_test_dir='tests',
    license='Apache 2.0',
    keywords='gcp google cloud platform security tools',
    entry_points={
        'console_scripts': [
            'forseti_scanner = google.cloud.forseti.stubs:RunForsetiScanner',
            'forseti_enforcer = google.cloud.forseti.stubs:RunForsetiEnforcer',
            'forseti_notifier = google.cloud.forseti.stubs:RunForsetiNotifier',
            'forseti_api = google.cloud.forseti.stubs:RunForsetiApi',
            'forseti_iam = google.cloud.forseti.stubs:RunExplainCli',
        ]
    },
    zip_safe=False,   # Set to False: apputils doesn't like zip_safe eggs
)
