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
import sys

from install.util import build_protos
from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install

import google.cloud.forseti

FORSETI_VERSION = google.cloud.forseti.__version__

NAMESPACE_PACKAGES = [
    'google',
    'google.cloud'
]

REQUIRED_PACKAGES = [
    # Installation related.
    'anytree>=2.1.4',
    'futures>=3.0.5',
    'google-api-python-client>=1.6.1',
    'google-auth>=1.4.1',
    'google-auth-httplib2>=0.0.3',
    'Jinja2>=2.9.5',
    'jmespath>=0.9.3',
    'MySQL-python>=1.2.5',
    'netaddr>=0.7.19',
    'PyYAML>=3.12',
    'pygraph>=0.2.1',
    'python-dateutil>=2.7.3',
    'ratelimiter>=1.1.0',
    'retrying>=1.3.3',
    'requests[security]>=2.18.4',
    'sendgrid>=3.6.3',
    'simple-crypt>=4.1.7',
    'unicodecsv>=0.14.1',
    # Setup related.
    'grpcio',
    'grpcio-tools',
    'protobuf>=3.2.0',
    # Testing related.
    'mock>=2.0.0',
    'parameterized>=0.6.1',
    'ruamel.yaml==0.15.37',
    'pylint',
    'pylint-quotes',
    'SQLAlchemy>=1.1.9,<1.3.0',
    'sqlalchemy-migrate>=0.11.0'
]

if sys.version_info < (2, 7):
    sys.exit('Sorry, Python < 2.7 is not supported.')

if sys.version_info.major > 2:
    sys.exit('Sorry, Python 3 is not supported.')


def build_forseti_protos(clean_only=False):
    """Clean and optionally Build protos.

      Args:
        clean_only (boolean): Whether to only clean previously built protos.
    """
    abs_path = os.path.abspath(__file__)
    build_protos.clean(abs_path)
    if not clean_only:
        build_protos.make_proto(abs_path)


class BuildProtosCommand(install):
    """A command to build protos in all children directories."""

    def run(self):
        build_forseti_protos()


class CleanProtosCommand(install):
    """A command to clean protos in all children directories."""

    def run(self):
        build_forseti_protos(clean_only=True)


class PostInstallCommand(install):
    """Post installation command."""

    def run(self):
        build_forseti_protos()
        install.do_egg_install(self)


setup(
    name='forseti-security',
    version=FORSETI_VERSION,
    description='Forseti Security tools',
    author='Google LLC.',
    author_email='opensource@google.com',
    url='https://github.com/GoogleCloudPlatform/forseti-security',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License'
    ],
    cmdclass={
        'build_protos': BuildProtosCommand,
        'clean_protos': CleanProtosCommand,
        'install': PostInstallCommand,
    },
    install_requires=REQUIRED_PACKAGES,
    setup_requires=REQUIRED_PACKAGES,
    tests_require=REQUIRED_PACKAGES,
    packages=find_packages(exclude=[
        '*.tests', '*.tests.*', 'tests.*', 'tests']),
    include_package_data=True,
    package_data={
        '': ['cloud/forseti/common/email_templates/*.jinja',
             'cloud/forseti/common/gcp_api/discovery_documents/*.json']
    },
    namespace_packages=NAMESPACE_PACKAGES,
    license='Apache 2.0',
    keywords='gcp google cloud platform security tools',
    entry_points={
        'console_scripts': [
            'forseti_enforcer = google.cloud.forseti.stubs:RunForsetiEnforcer',
            'forseti_server = google.cloud.forseti.stubs:RunForsetiServer',
            'forseti = google.cloud.forseti.stubs:RunForsetiCli',
        ]
    },
    zip_safe=False,   # Set to False: apputils doesn't like zip_safe eggs
)
