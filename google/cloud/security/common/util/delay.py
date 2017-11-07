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

"""Tool used to delay initial execution of a function."""

from functools import wraps
import time


def delay(delay_by, clock=None):
    """Delays execution of the decorated function.

    Args:
        delay_by(int): Number of seconds to delay by.
        clock(time.sleep): Clock used to measure delay (mainly used for tests).
            If none is provided clock will be created.

    Returns:
        function: Wrapped function.

    """
    if clock is None:
        clock = time.sleep

    def decorate(func):
        """Decorator function for the wrapper.

        Args:
            func(function): passes a function into the wrapper.

        Returns:
            function: Wrapped function.

        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            """Wrapper function for clock.

            Args:
                *args: Passed in arguments.
                **kwargs: Passed in keyword arguments.

            Returns:
                function: clock after its been delayed by the passed in
                    argument.

            """
            clock(delay_by)
            return func(*args, **kwargs)

        return wrapper

    return decorate
