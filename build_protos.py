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

"""A script to prepare the source tree for building."""

# Modeled after https://github.com/google/grr/blob/master/makefile.py
# TODO: revisit whether this needs to use gflags/apputils. Running the
# makefile from setup.py (even when the setup_requires has gflags/apputils)
# does not work. If we pass a PYTHONPATH to include the gflags/apputils
# eggs in the subprocess env, the makefile works, but the installed packages
# do not include gflags or apputils.

import argparse
import logging
import os
import subprocess


def isGrpcServiceDir(root, files):
  return "/service_protos" in root or ".grpc_service" in files

def Clean():
  """Clean out compiled protos."""
  # Start running from one directory above the directory which is found by
  # this scripts's location as __file__.
  logging.info("Cleaning out compiled protos.")
  cwd = os.path.dirname(os.path.abspath(__file__))

  # Find all the .proto files.
  for (root, dirs, files) in os.walk(cwd):
    if isGrpcServiceDir(root, files):
      logging.info("Skipping grpc service directory: %s"%root)
      dirs[:] = []
      continue
    for filename in files:
      full_filename = os.path.join(root, filename)
      if full_filename.endswith("_pb2.py") or full_filename.endswith(
          "_pb2.pyc"):
        os.unlink(full_filename)


def MakeProto():
  """Make sure our protos have been compiled to python libraries."""
  # Start running from one directory above the directory which is found by
  # this scripts's location as __file__.
  cwd = os.path.dirname(os.path.abspath(__file__))

  # Find all the .proto files.
  protos_to_compile = []
  for (root, dirs, files) in os.walk(cwd):
    if isGrpcServiceDir(root, files):
      logging.info("Skipping grpc service directory: %s"%root)
      dirs[:] = []
      continue
    for filename in files:
      full_filename = os.path.join(root, filename)
      if full_filename.endswith(".proto"):
        proto_stat = os.stat(full_filename)
        try:
          pb2_stat = os.stat(full_filename.rsplit(".", 1)[0] + "_pb2.py")
          if pb2_stat.st_mtime >= proto_stat.st_mtime:
            continue

        except (OSError, IOError):
          pass

        protos_to_compile.append(full_filename)

  if not protos_to_compile:
    logging.info("No protos needed to be compiled.")
  else:
    # Find the protoc compiler.
    protoc = os.environ.get("PROTOC", "protoc")
    try:
      output = subprocess.check_output([protoc, "--version"])
    except (IOError, OSError):
      raise RuntimeError("Unable to launch %s protoc compiler. Please "
                         "set the PROTOC environment variable.", protoc)

    pieces = output.split(" ")
    try:
        version_pieces = pieces[1].strip().split(".")
        protoc_version = float("{}.{}".format(version_pieces[0],
                                              version_pieces[1]))
    except (IndexError, ValueError):
        raise RuntimeError("Incompatible protoc compiler: %s" % output)

    if protoc_version < 3:
      raise RuntimeError("Incompatible protoc compiler detected. "
                         "We need >= 3.0.0; you have %s" % output)

    for proto in protos_to_compile:
      logging.info("Compiling %s", proto)
      # The protoc compiler is too dumb to deal with full paths - it expects a
      # relative path from the current working directory.
      subprocess.check_call(
          [
              protoc,
              # Write the python files next to the .proto files.
              "--python_out=.",
              # Standard include paths.
              # We just bring google/proto/descriptor.proto with us to make it
              # easier to install.
              "--proto_path=.",
              os.path.relpath(proto, cwd)
          ],
          cwd=cwd)

def main(unused_argv=None):
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--clean", dest="clean", action="store_true",
                            help="Clean out compiled protos")
    arg_parser.set_defaults(feature=False)
    args = arg_parser.parse_args()

    if args.clean:
      Clean()
    MakeProto()


if __name__ == "__main__":
    main()
