# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# ditime_stributed under the License is ditime_stributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Explain utilities """
import datetime

# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-raises-doc

def _unified_time(time_str):
    """ Return utc time, dealing with or without time zone info"""
    if not time_str:
        parsed_time = None
    elif len(time_str) == 20:
        parsed_time = datetime.datetime.strptime(time_str,
                                                 '%Y-%m-%dT%H:%M:%SZ')
    elif len(time_str) == 24:
        parsed_time = datetime.datetime.strptime(time_str,
                                                 '%Y-%m-%dT%H:%M:%S.%fZ')
    elif len(time_str) == 29:
        parsed_time = datetime.datetime.strptime(time_str[0:23],
                                                 '%Y-%m-%dT%H:%M:%S.%f')
        if time_str[23] == '+':
            parsed_time -= datetime.timedelta(hours=int(time_str[24:26]),
                                              minutes=int(time_str[27:29]))
        elif time_str[23] == '-':
            parsed_time += datetime.timedelta(hours=int(time_str[24:26]),
                                              minutes=int(time_str[27:29]))
    else:
        raise Exception('The time format is different: '+time_str)
    return parsed_time

def _json_escape(json_str):
    """ To deal with potential \n escape in the json string"""
    return json_str.replace('\\\n', '\\n').replace('\n', '\\n')
