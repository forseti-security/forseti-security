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

"""Errors module."""


class Error(Exception):
    """Base error class for the module."""


class InvalidResourceTypeError(Error):
    """Invalid Resource Type Error."""
    pass


class InvalidIamPolicyError(Error):
    """Error for invalid IAM policies."""
    pass


class InvalidIamAuditConfigError(Error):
    """Error for invalid IAM Audit Configs."""
    pass


class InvalidIamPolicyBindingError(Error):
    """Error for invalid IAM policy bindings."""
    pass


class InvalidIamPolicyMemberError(Error):
    """Error for invalid IAM policy members."""
    pass


class InvalidGroupMemberError(Error):
    """Error for invalid Group members."""
    pass
