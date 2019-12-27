# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import sys
import yaml

FORSETI_SERVER_CONFIG = '/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml'


class ServerConfigActions:

    @staticmethod
    def read_server_config():
        try:
            with open(FORSETI_SERVER_CONFIG, 'r') as stream:
                config = yaml.safe_load(stream)
            print('Successfully read server config...')
            return config
        except Exception as e:
            print(f'ERROR: Unable to read server config. {e}')
            sys.exit(-2)

    @staticmethod
    def reload_server_config():
        try:
            cmd = ['forseti', 'server', 'configuration', 'reload']
            forseti = subprocess.run(cmd,
                                     stderr=subprocess.PIPE,
                                     stdout=subprocess.PIPE)
            if forseti.returncode != 0:
                print(f'ERROR: Forseti returned a nonzero exit code. {forseti.returncode}')
                sys.exit(forseti.returncode)
            print('Successfully reloaded server config...')
        except Exception as e:
            print(f'ERROR: Unable to reload server config. {e}')
            sys.exit(-4)

    @staticmethod
    def set_cai_enabled(cai_enabled):
        print(f'Setting CAI enabled to {cai_enabled}')
        try:
            config = ServerConfigActions.read_server_config()
            value = True if cai_enabled.lower() == 'true' else False
            config['inventory']['cai']['enabled'] = value
            ServerConfigActions.write_server_config(config)
            print('Successfully updated CAI enabled...')
        except Exception as e:
            print(f'ERROR: Unable to set CAI enabled. {e}')
            sys.exit(1)

    @staticmethod
    def set_inventory_summary_email_enabled(enabled):
        print(f'Setting inventory summary email enabled to {enabled}')
        try:
            config = ServerConfigActions.read_server_config()
            value = True if enabled.lower() == 'true' else False
            config['notifier']['inventory']['email_summary']['enabled'] = value
            ServerConfigActions.write_server_config(config)
            print('Successfully updated inventory summary email enabled...')
        except Exception as e:
            print(f'ERROR: Unable to set inventory summary email enabled. {e}')
            sys.exit(2)

    @staticmethod
    def write_server_config(config):
        try:
            with open(FORSETI_SERVER_CONFIG, 'w', encoding='utf8') as outfile:
                yaml.dump(config,
                          outfile,
                          allow_unicode=True,
                          default_style=None,
                          default_flow_style=False)
            print('Successfully wrote to server config...')
        except Exception as e:
            print(f'ERROR: Unable to write server config. {e}')
            sys.exit(-3)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('No action provided!')
        sys.exit(-1)

    action_method = getattr(ServerConfigActions, sys.argv[1])
    print(f'Running action {action_method}')
    action_method(*sys.argv[2:])
