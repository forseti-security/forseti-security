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

"""Regex utility module."""

import re


# pylint: disable=anomalous-backslash-in-string
def escape_and_globify(pattern_string, wildcard_is_zero_or_more=False):
    """Given a pattern string with a glob, create actual regex pattern.

    To require > 0 length glob, change the "*" to ".+". This is to handle
    strings like "\*@company.com". (The actual regex would probably be
    ".\*@company.com", except that we don't want to match zero-length
    usernames before the "@".)

    Special case the pattern '*' to match 0 or more characters.

    Args:
        pattern_string (str): The pattern string of which to make a regex.
        wildcard_is_zero_or_more (bool): Whether the wildcard designates
            0 or more versus 1 or more for wildcards after the prefix.

    Returns:
        str: The pattern string, escaped except for the "*", which is
            transformed into ".+" (match on one or more characters).
    """
    if pattern_string is None:
        return None

    # pylint: enable=anomalous-backslash-in-string
    if pattern_string == '*':
        return '^.*$'

    # TODO(2189): Make wildcards always 0 or more.
    replace = '.*' if wildcard_is_zero_or_more else '.+'

    return '^{}$'.format(re.escape(pattern_string).replace('\\*', replace))
