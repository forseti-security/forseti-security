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

"""Forseti Security."""

import argparse as ap
import sys

execfile('./version.py')


def create_parser(parser_cls):
    main_parser = define_parent_parser(parser_cls)
    service_subparsers = main_parser.add_subparsers(
        title='service',
        dest='service')
    define_info_parser(service_subparsers)
    define_auditor_parser(service_subparsers)
    return main_parser

def define_parent_parser(parser_cls):
    parent_parser = parser_cls()
    parent_parser.add_argument(
        '--config',
        help='Forseti conf')
    return parent_parser

def define_info_parser(parent_parser):
    service_parser = parent_parser.add_parser('info', help='Info')
    service_parser.add_argument(
        '--version',
        action='store_true',
        help='Forseti version')
    return service_parser

def define_auditor_parser(parent_parser):
    service_parser = parent_parser.add_parser('auditor', help='Auditor')
    return service_parser

def main(args, parser_cls=ap.ArgumentParser):
    parser = create_parser(parser_cls)
    cli_config = parser.parse_args(args)
    if cli_config.version:
        print('Forseti version: %s' % __version__)
        sys.exit(0)
    if not cli_config.config:
        print('Missing config path')
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
