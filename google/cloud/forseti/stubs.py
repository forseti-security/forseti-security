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

"""Provide entry points for the console script entry points."""


# pylint: disable=invalid-name
def RunForsetiEnforcer():
    """Run Forseti Enforcer module."""
    import google.cloud.forseti.enforcer.enforcer as forseti_enforcer
    forseti_enforcer.main()


def RunForsetiServer():
    """Run Forseti API server."""
    import google.cloud.forseti.services.server as forseti_server
    forseti_server.main()


def RunForsetiCli():
    """Run Forseti CLI."""
    import google.cloud.forseti.services.cli as forseti_cli
    forseti_cli.main()
