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

"""Forseti Server program."""

# pylint: disable=line-too-long
import argparse
import os
import sys
import time

from concurrent import futures
import grpc

from google.cloud.forseti.common.util import logger

from google.cloud.forseti.services.base.config import ServiceConfig
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.model.service import GrpcModellerFactory
from google.cloud.forseti.services.notifier.service import GrpcNotifierFactory
from google.cloud.forseti.services.scanner.service import GrpcScannerFactory
from google.cloud.forseti.services.server_config.service import GrpcServerConfigFactory

LOGGER = logger.get_logger(__name__)

SERVICE_MAP = {
    'explain': GrpcExplainerFactory,
    'inventory': GrpcInventoryFactory,
    'scanner': GrpcScannerFactory,
    'notifier': GrpcNotifierFactory,
    'model': GrpcModellerFactory,
    'server': GrpcServerConfigFactory
}


def serve(endpoint,
          services,
          forseti_db_connect_string,
          config_file_path,
          log_level,
          enable_console_log,
          max_workers=32,
          wait_shutdown_secs=3):
    """Instantiate the services and serves them via gRPC.

    Args:
        endpoint (str): the server channel endpoint
        services (list): services to register on the server
        forseti_db_connect_string (str): Forseti database string
        config_file_path (str): Path to Forseti configuration file.
        log_level (str): Sets the threshold for Forseti's logger.
        enable_console_log (bool): Enable console logging.
        max_workers (int): maximum number of workers for the crawler
        wait_shutdown_secs (int): seconds to wait before shutdown

    Raises:
        Exception: No services to start
    """

    # Configuring log level for the application
    logger.set_logger_level_from_config(log_level)

    if enable_console_log:
        logger.enable_console_log()

    factories = []
    for service in services:
        factories.append(SERVICE_MAP[service])

    if not factories:
        raise Exception('No services to start.')

    # Server config service is always started.
    factories.append(SERVICE_MAP['server'])

    config = ServiceConfig(
        forseti_config_file_path=config_file_path,
        forseti_db_connect_string=forseti_db_connect_string,
        endpoint=endpoint)
    config.update_configuration()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers))
    for factory in factories:
        factory(config).create_and_register_service(server)

    server.add_insecure_port(endpoint)
    server.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            server.stop(wait_shutdown_secs).wait()
            return


def check_args(args):
    """Make sure the required args are present and valid.

    The exit codes are arbitrary and just serve the purpose of facilitating
    distinction betweeen the various error cases.

    Args:
        args (dict): the command line args

    Returns:
        tuple: 2-tuple with an exit code and error message.
    """
    if not args['services']:
        return (1, 'ERROR: please specify at least one service.')

    if not args['config_file_path']:
        return (2, 'ERROR: please specify the Forseti config file.')

    if not os.path.isfile(args['config_file_path']):
        return (3, 'ERROR: "%s" is not a file.' % args['config_file_path'])

    if not os.access(args['config_file_path'], os.R_OK):
        return(4, 'ERROR: "%s" is not readable.' % args['config_file_path'])

    if not args['forseti_db']:
        return(5, 'ERROR: please specify the Forseti database string.')

    return (0, 'All good!')


# pylint: enable=too-many-locals


def main():
    """Run."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--endpoint',
        default='[::]:50051',
        help='Server endpoint')
    parser.add_argument(
        '--forseti_db',
        help=('Forseti database string, formatted as '
              '"mysql://<db_user>@<db_host>:<db_port>/<db_name>"'))
    parser.add_argument(
        '--config_file_path',
        help='Path to Forseti configuration file.')
    services = sorted(SERVICE_MAP.keys())
    parser.add_argument(
        '--services',
        nargs='+',
        choices=services,
        help=('Forseti services i.e. at least one of: %s.' %
              ', '.join(services)))
    parser.add_argument(
        '--log_level',
        default='info',
        choices=['debug', 'info', 'warning', 'error'],
        help='Sets the threshold for Forseti\'s logger.'
             ' Logging messages which are less severe'
             ' than the level you set will be ignored.')
    parser.add_argument(
        '--enable_console_log',
        action='store_true',
        help='Print log to console.')

    args = vars(parser.parse_args())

    exit_code, error_msg = check_args(args)

    if exit_code:
        sys.stderr.write('%s\n\n' % error_msg)
        parser.print_usage()
        sys.exit(exit_code)

    serve(args['endpoint'],
          args['services'],
          args['forseti_db'],
          args['config_file_path'],
          args['log_level'],
          args['enable_console_log'])


if __name__ == '__main__':
    main()
