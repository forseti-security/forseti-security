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

"""A script to prepare the source tree for building."""

import os
import subprocess

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

def is_grpc_service_dir(files):
    """Returns true iff the directory hosts a gRPC service.

        Args:
          files (list): The 'files' output of os.walk().

        Returns:
           Boolean: True if '.grpc_service' is in the files, otherwise False.
    """
    return '.grpc_service' in files


def clean(path):
    """Clean out compiled protos.

        Args:
          path (string): A reference path to start from.
    """
    # Start running from one directory above the directory which is found by
    # this scripts's location as __file__.
    LOGGER.info('Cleaning out compiled protos.')
    cwd = os.path.dirname(path)

    # Find all the .proto files.
    for (root, _, files) in os.walk(cwd):
        if is_grpc_service_dir(files):
            LOGGER.info(
                'Cleaning a service proto, restart any servers: %s',
                root)
        for filename in files:
            full_filename = os.path.join(root, filename)
            if full_filename.endswith('_pb2.py') or full_filename.endswith(
                    '_pb2.pyc'):
                os.unlink(full_filename)


def make_proto(path):
    """Make sure our protos have been compiled to python libraries.

        Args:
          path (string): A reference path to start from.
    """
    cwd = os.path.dirname(path)

    # Find all the .proto files.
    protos_to_compile = []
    for (root, _, files) in os.walk(cwd):
        for filename in files:
            full_filename = os.path.join(root, filename)
            if full_filename.endswith('.proto'):
                proto_stat = os.stat(full_filename)
                try:
                    pb2_stat = os.stat(
                        full_filename.rsplit(
                            '.', 1)[0] + '_pb2.py')
                    if pb2_stat.st_mtime >= proto_stat.st_mtime:
                        continue

                except (OSError, IOError):
                    pass

                protos_to_compile.append(full_filename)

    if not protos_to_compile:
        LOGGER.info('No protos needed to be compiled.')
    else:
        for proto in protos_to_compile:
            LOGGER.info('Compiling %s', proto)
            protodir, protofile = os.path.split(proto)

            subprocess.check_call(
                [
                    'python',
                    '-m',
                    'grpc_tools.protoc',
                    '-I.',
                    '--python_out=.',
                    '--grpc_python_out=.',
                    protofile,
                ],
                cwd=protodir)
