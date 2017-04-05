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

"""Util Errors module."""


class Error(Exception):
    """Base error class for the module."""


class EmailSendError(Error):
    """Unable to send email."""
    pass


class InvalidFileExtensionError(Error):
    """No parser exists for the given file extension."""
    pass


class InvalidParserTypeError(Error):
    """No parser exists for the given parser type."""
    pass


class MetadataServerHttpError(Error):
    """An error for handling HTTP errors with the metadata server."""
    pass
