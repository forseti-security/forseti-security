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

"""Wrapper functions used to record and replay API responses."""

import collections
import functools
import os
import pickle
from googleapiclient import errors
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
RECORD_ENVIRONMENT_VAR = 'FORSETI_RECORD_FILE'
REPLAY_ENVIRONMENT_VAR = 'FORSETI_REPLAY_FILE'


def _key_from_request(request):
    """Generate a unique key from a request.

    Args:
        request (HttpRequest): a googleapiclient HttpRequest object.

    Returns:
        str: A unique key from the request uri and body.
    """
    return '{}{}'.format(request.uri, request.body)


def record(requests):
    """Record and serialize GCP API call answers.

    Args:
        requests (dict): A dictionary to store a copy of all requests and
            responses in, before pickling.

    Returns:
        function: Decorator function.
    """
    def decorate(f):
        """Decorator function for the wrapper.

        Args:
            f(function): passes a function into the wrapper.

        Returns:
            function: Wrapped function.
        """
        @functools.wraps(f)
        def record_wrapper(self, request, *args, **kwargs):
            """Record and serialize GCP API call answers.

            Args:
                self (object): Self of the caller.
                request (HttpRequest): The HttpRequest object to execute.
                **args (list): Additional args to pass through to function.
                **kwargs (dict): Additional key word args to pass through to
                    function.

            Returns:
                object: The result from the wrapped function.

            Raises:
                HttpError: Raised by any fatal HTTP error when executing the
                    HttpRequest.
                Exception: Any exception raised by the wrapped function.
            """
            record_file = os.environ.get(RECORD_ENVIRONMENT_VAR, None)
            if not record_file:
                return f(self, request, *args, **kwargs)

            with file(record_file, 'w') as outfile:
                pickler = pickle.Pickler(outfile)
                request_key = _key_from_request(request)
                results = requests.setdefault(
                    request_key, collections.deque())
                try:
                    result = f(self, request, *args, **kwargs)
                    obj = {
                        'exception_args': None,
                        'raised': False,
                        'request': request.to_json(),
                        'result': result,
                        'uri': request.uri}
                    results.append(obj)
                    return result
                except errors.HttpError as e:
                    # HttpError won't unpickle without all three arguments.
                    obj = {
                        'raised': True,
                        'request': request.to_json(),
                        'result': e.__class__,
                        'uri': request.uri,
                        'exception_args': (e.resp, e.content, e.uri)
                    }
                    results.append(obj)
                    raise
                except Exception as e:
                    LOGGER.exception(e)
                    obj = {
                        'raised': True,
                        'request': request.to_json(),
                        'result': e.__class__,
                        'uri': request.uri,
                        'exception_args': [str(e)]
                    }
                    results.append(obj)
                    raise
                finally:
                    LOGGER.debug('Recording key %s', request_key)
                    pickler.dump(requests)
                    outfile.flush()

        return record_wrapper

    return decorate


def replay(requests):
    """Record and serialize GCP API call answers.

    Args:
        requests (dict): A dictionary to store a copy of all requests and
            responses in, after unpickling.

    Returns:
        function: Decorator function.
    """
    def decorate(f):
        """Replay GCP API call answers.

        Args:
            f (function): Function to decorate

        Returns:
            function: Wrapped function.
        """
        @functools.wraps(f)
        def replay_wrapper(self, request, *args, **kwargs):
            """Replay and deserialize GCP API call answers.

            Args:
                self (object): Self of the caller.
                request (HttpRequest): The HttpRequest object to execute.
                **args (list): Additional args to pass through to function.
                **kwargs (dict): Additional key word args to pass through to
                    function.

            Returns:
                object: The result object from the previous recording.

            Raises:
                Exception: Any exception raised during the previous recording.
            """
            replay_file = os.environ.get(REPLAY_ENVIRONMENT_VAR, None)
            if not replay_file:
                return f(self, request, *args, **kwargs)

            if not requests:
                LOGGER.info('Loading replay file %s.', replay_file)
                with file(replay_file) as infile:
                    unpickler = pickle.Unpickler(infile)
                    requests.update(unpickler.load())

            request_key = _key_from_request(request)
            if request_key in requests:
                results = requests[request_key]
                # Pull the first result from the queue.
                obj = results.popleft()
                if obj['raised']:
                    raise obj['result'](*obj['exception_args'])
                return obj['result']
            else:
                LOGGER.warning(
                    'Request URI %s with body %s not found in recorded '
                    'requests, executing live http request instead.',
                    request.uri, request.body)
                return f(self, request, *args, **kwargs)

        return replay_wrapper

    return decorate
