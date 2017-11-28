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

"""Utils for IAM Explain testing."""

import sys
import simplecrypt


def copy_file_encrypt(dst_filename, src_filename, passphrase):
    """Copy and encrypt a file with passphrase."""

    with file(src_filename, 'rb') as infile:
        with file(dst_filename, 'wb') as outfile:
            outfile.write(simplecrypt.encrypt(passphrase, infile.read()))
    return dst_filename


def copy_file_decrypt(dst_filename, src_filename, passphrase):
    """Copy and decrypt a file with passphrase."""

    with file(src_filename, 'rb') as infile:
        with file(dst_filename, 'wb') as outfile:
            outfile.write(simplecrypt.decrypt(passphrase, infile.read()))
    return dst_filename


if __name__ == '__main__':
    copy_file_encrypt(sys.argv[1], sys.argv[2], sys.argv[3])
