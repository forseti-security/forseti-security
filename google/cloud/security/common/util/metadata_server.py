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

"""Metadata server utilities.

The metadata server is only accessible on GCE.
"""

import httplib
import socket

METADATA_SERVER_CONN_TIMEOUT = 2


def can_reach_metadata_server():
    """Determine if we can reach the metadata server.

    Returns:
        True if metadata server can be reached, False otherwise.
    """
    conn = httplib.HTTPConnection('metadata.google.internal',
                                  timeout=METADATA_SERVER_CONN_TIMEOUT)
    can_reach_md_server = False

    try:
        conn.request('GET', '/computeMetadata/v1/instance/id',
                     None, {'Metadata-Flavor': 'Google'})
        res = conn.getresponse()
        can_reach_md_server = (res and res.status == 200)
    except socket.error:
        # Don't care about showing that an error happened.
        pass

    finally:
        conn.close()

    return can_reach_md_server
