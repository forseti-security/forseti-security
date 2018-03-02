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

"""Test Utils for Forseti unit tests."""

import collections
import contextlib
import json
import logging
import mock
import os
import tempfile
import unittest
import socket
from google.cloud.forseti.common.util import logger


def get_available_port():
    """Get a port that is available to use"""
    sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sckt.bind(("",0))
    sckt.listen(1)
    port = sckt.getsockname()[1]
    sckt.close()
    return port

@contextlib.contextmanager
def create_temp_file(data):
    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.write(data)
    temp.close()
    try:
        yield temp.name
    finally:
        os.unlink(temp.name)



class ForsetiTestCase(unittest.TestCase):
    """Forseti base class for tests."""

    def __init__(self, *args, **kwargs):
        super(ForsetiTestCase, self,).__init__(*args, **kwargs)
        logger.set_logger_level(logging.ERROR)

    def assertStartsWith(self, actual, expected_start):
        """Assert that actual.startswith(expected_start) is True.
            Args:
            actual: str
            expected_start: str
        """
        if not actual.startswith(expected_start):
            self.fail('%r does not start with %r' % (actual, expected_start))

    def assertSameStructure(self, a, b, aname='a', bname='b', msg=None):
        """Asserts that two values contain the same structural content.

        The two arguments should be data trees consisting of trees of dicts and
        lists. They will be deeply compared by walking into the contents of
        dicts and lists; other items will be compared using the == operator.
        If the two structures differ in content, the failure message will
        indicate the location within the structures where the first
        difference is found. This may be helpful when comparing large
        structures.

        Args:
            a: The first structure to compare.
            b: The second structure to compare.
            aname: Variable name to use for the first structure in assertion
                messages.
            bname: Variable name to use for the second structure.
            msg: Additional text to include in the failure message.
        """

        # Accumulate all the problems found so we can report all of them at once
        # rather than just stopping at the first
        problems = []

        _WalkStructureForProblems(a, b, aname, bname, problems)

        # Avoid spamming the user toooo much
        max_problems_to_show = self.maxDiff // 80
        if len(problems) > max_problems_to_show:
            problems = problems[0:max_problems_to_show-1] + ['...']

        if problems:
            failure_message = '; '.join(problems)
            if msg:
                failure_message += (': ' + msg)
            self.fail(failure_message)

_INT_TYPES = (int, long)  # Sadly there is no types.IntTypes defined for us.


def _WalkStructureForProblems(a, b, aname, bname, problem_list):
  """The recursive comparison behind assertSameStructure."""
  if type(a) != type(b) and not (
      isinstance(a, _INT_TYPES) and isinstance(b, _INT_TYPES)):
    # We do not distinguish between int and long types as 99.99% of Python 2
    # code should never care.  They collapse into a single type in Python 3.
    problem_list.append('%s is a %r but %s is a %r' %
                        (aname, type(a), bname, type(b)))
    # If they have different types there's no point continuing
    return

  if isinstance(a, collections.Mapping):
    for k in a:
      if k in b:
        _WalkStructureForProblems(a[k], b[k],
                                  '%s[%r]' % (aname, k), '%s[%r]' % (bname, k),
                                  problem_list)
      else:
        problem_list.append('%s has [%r] but %s does not' % (aname, k, bname))
    for k in b:
      if k not in a:
        problem_list.append('%s lacks [%r] but %s has it' % (aname, k, bname))

  # Strings are Sequences but we'll just do those with regular !=
  elif isinstance(a, collections.Sequence) and not isinstance(a, basestring):
    minlen = min(len(a), len(b))
    for i in xrange(minlen):
      _WalkStructureForProblems(a[i], b[i],
                                '%s[%d]' % (aname, i), '%s[%d]' % (bname, i),
                                problem_list)
    for i in xrange(minlen, len(a)):
      problem_list.append('%s has [%i] but %s does not' % (aname, i, bname))
    for i in xrange(minlen, len(b)):
      problem_list.append('%s lacks [%i] but %s has it' % (aname, i, bname))

  else:
    if a != b:
      problem_list.append('%s is %r but %s is %r' % (aname, a, bname, b))


def get_datafile_path(start_loc, filename):
    """Get the path for a data file."""
    return os.path.join(
        os.path.dirname(os.path.abspath(start_loc)),
        'data',
        filename)

def load_json(json_file_path):
    """Load json data from a file."""
    data = {}
    with open(json_file_path, 'r') as filedata:
        data = json.load(filedata)
    return data
