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

""" IAM Explain utilities. """

import logging


def logcall(f, level=logging.CRITICAL):
    """Call logging decorator."""
    def wrapper(*args, **kwargs):
        """Implements the log wrapper including parameters and result."""
        logging.log(level, 'enter %s(%s)', f.__name__, args)
        result = f(*args, **kwargs)
        logging.log(level, 'exit %s(%s) -> %s', f.__name__, args, result)
        return result
    return wrapper


def mutual_exclusive(lock):
    """ Mutex decorator. """
    def wrap(f):
        """Decorator generator."""
        def function(*args, **kw):
            """Decorated functionality, mutexing wrapped function."""
            lock.acquire()
            try:
                return f(*args, **kw)
            finally:
                lock.release()
        return function
    return wrap


def oneof(*args):
    """Returns true iff one of the parameters is true."""
    return len([x for x in args if x]) == 1
