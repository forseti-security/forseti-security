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

"""Provide entry points for the console script entry points.

Since the Forseti tools use google-apputils, the setuptools console script
entry points are handled a little differently.  For more information on the
apputils run_script_module, refer to:

https://github.com/google/google-apputils/blob/master/google/apputils/run_script_module.py
"""

# pylint: disable=invalid-name

from google.apputils import run_script_module

def RunForsetiInventory():
    """Run Forseti Inventory module."""
    import google.cloud.security.inventory.inventory_loader as forseti_inventory
    run_script_module.RunScriptModule(forseti_inventory)

def RunForsetiScanner():
    """Run Forseti Scanner module."""
    import google.cloud.security.scanner.scanner as forseti_scanner
    run_script_module.RunScriptModule(forseti_scanner)

def RunForsetiEnforcer():
    """Run Forseti Enforcer module."""
    import google.cloud.security.enforcer.enforcer as forseti_enforcer
    run_script_module.RunScriptModule(forseti_enforcer)

def RunForsetiNotifier():
    """Run Forseti Notifier module."""
    import google.cloud.security.notifier.notifier as forseti_notifier
    run_script_module.RunScriptModule(forseti_notifier)

# TODO: Investigate improving so the pylint disable isn't needed.
# pylint: disable=invalid-name
# pylint: disable=E0401
def RunForsetiApi():
    """Run Forseti API server."""
    import google.cloud.security.api.server as forseti_api
    run_script_module.RunScriptModule(forseti_api)
