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

"""A script to prepare the source tree for building."""

import argparse
import logging
import os
import subprocess


def is_grpc_service_dir(files):
    """Returns true iff the directory hosts a gRPC service.
        Args:
            files(list): A list of files from os.walk().
        Returns:
            Boolean: True if ".grpc_service" is in the list.
    """
    return ".grpc_service" in files


def clean():
    """Clean out compiled protos."""
    # Start running from one directory above the directory which is found by
    # this scripts's location as __file__.
    logging.info("Cleaning out compiled protos.")
    cwd = os.path.dirname(os.path.abspath(__file__))

    # Find all the .proto files.
    for (root, dirs, files) in os.walk(cwd):
        if is_grpc_service_dir(files):
            logging.info('Skipping grpc service directory: %s', root)
            dirs[:] = []
            continue
        for filename in files:
            full_filename = os.path.join(root, filename)
            if full_filename.endswith("_pb2.py") or full_filename.endswith(
                    "_pb2.pyc"):
                os.unlink(full_filename)


def make_proto_service(root):
    """Generate a proto service from the definition file.
        Args:
            root(str): The root of the current working directory.t
    """
    script_basename = "mkproto.sh"
    script_path = os.path.join(root, script_basename)
    subprocess.check_call(
        [
            "/bin/sh",
            script_path
        ])


def make_proto():
    """Make sure our protos have been compiled to python libraries."""
    # Start running from one directory above the directory which is found by
    # this scripts's location as __file__.
    cwd = os.path.dirname(os.path.abspath(__file__))

    # Find all the .proto files.
    protos_to_compile = []
    for (root, _, files) in os.walk(cwd):
        for filename in files:
            full_filename = os.path.join(root, filename)
            if full_filename.endswith(".proto"):
                proto_stat = os.stat(full_filename)
                try:
                    pb2_stat = os.stat(
                        full_filename.rsplit(
                            ".", 1)[0] + "_pb2.py")
                    if pb2_stat.st_mtime >= proto_stat.st_mtime:
                        continue

                except (OSError, IOError):
                    pass

                protos_to_compile.append(full_filename)

    if not protos_to_compile:
        logging.info("No protos needed to be compiled.")
    else:
        for proto in protos_to_compile:
            logging.info("Compiling %s", proto)
            protodir, protofile = os.path.split(proto)

            subprocess.check_call(
                [
                    "python",
                    "-m",
                    "grpc_tools.protoc",
                    "-I.",
                    "--python_out=.",
                    "--grpc_python_out=.",
                    protofile,
                ],
                cwd=protodir)


def main():
    """Generate python code from .proto files."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--clean", dest="clean", action="store_true",
                            help="Clean out compiled protos")
    arg_parser.set_defaults(feature=False)
    args = arg_parser.parse_args()

    if args.clean:
        clean()
    make_proto()


if __name__ == "__main__":
    main()