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

"""Provide entry points for the console script entry points.

Since the Forseti tools use google-apputils, the setuptools console script
entry points are handled a little differently.  For more information on the
apputils run_script_module, refer to:

https://github.com/google/google-apputils/blob/master/google/apputils/run_script_module.py
"""

# pylint: disable=invalid-name

from google.apputils import run_script_module


def RunForsetiScanner():
    """Run Forseti Scanner module."""
    import google.cloud.forseti.scanner.scanner as forseti_scanner
    run_script_module.RunScriptModule(forseti_scanner)


def RunForsetiEnforcer():
    """Run Forseti Enforcer module."""
    import google.cloud.forseti.enforcer.enforcer as forseti_enforcer
    run_script_module.RunScriptModule(forseti_enforcer)


def RunForsetiNotifier():
    """Run Forseti Notifier module."""
    import google.cloud.forseti.notifier.notifier as forseti_notifier
    run_script_module.RunScriptModule(forseti_notifier)


def RunForsetiServer():
    """Run Forseti API server."""
    import google.cloud.forseti.services.server as forseti_server
    run_script_module.RunScriptModule(forseti_server)


def RunForsetiCli():
    """Run Forseti CLI."""
    import google.cloud.forseti.services.cli as forseti_cli
    run_script_module.RunScriptModule(forseti_cli)
