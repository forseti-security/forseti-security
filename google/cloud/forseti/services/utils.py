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

"""Forseti Server utilities."""

from itertools import izip
import logging


# pylint: disable=protected-access


def autoclose_stream(f):
    """Decorator to close gRPC stream.

    Args:
        f (func): The function to decorate

    Returns:
        wrapper: wrapper of the decorator
    """

    def wrapper(*args):
        """Wrapper function, checks context state to close stream.

        Args:
            *args (list): All arguments provided to the wrapped function.

        Yields:
            object: Whatever the wrapped function yields to the stream.
        """

        def closed(context):
            """Returns true iff the connection is closed.

            Args:
                context (object): the connection to check

            Returns:
                bool: whether the connection is closed
            """

            return context._state.client == 'closed'

        context = args[-1]
        for result in f(*args):
            yield result
            if closed(context):
                return

    return wrapper


def logcall(f, level=logging.CRITICAL):
    """Call logging decorator.

    Args:
        f (func): The function to decorate
        level (str): the level of logging

    Returns:
        wrapper: wrapper of the decorator
    """

    def wrapper(*args, **kwargs):
        """Implements the log wrapper including parameters and result.

        Args:
            *args: All args provided to the wrapped function.
            **kwargs: All kwargs provided to the wrapped function.

        Returns:
            object: the f execution result
        """
        logging.log(level, 'enter %s(%s)', f.__name__, args)
        result = f(*args, **kwargs)
        logging.log(level, 'exit %s(%s) -> %s', f.__name__, args, result)
        return result

    return wrapper


def mutual_exclusive(lock):
    """ Mutex decorator.

    Args:
        lock (object): The lock to lock out exclusive method

    Returns:
        object: decorator generator
    """

    def wrap(f):
        """Decorator generator.

        Args:
            f (func): the function to decorate

        Returns:
            func: the decorated function
        """

        def func(*args, **kw):
            """Decorated functionality, mutexing wrapped function.

            Args:
                *args: All args provided to the wrapped function
                **kw: All kw provided to the wrapped function

            Returns:
                object: the execution results of f
            """
            lock.acquire()
            try:
                return f(*args, **kw)
            finally:
                lock.release()

        return func

    return wrap


def oneof(*args):
    """Returns true iff one of the parameters is true.

    Args:
        *args: arguments to check

    Returns:
        bool: true iff one of the parameters is true.
    """

    return len([x for x in args if x]) == 1


def full_to_type_name(full_resource_name):
    """Creates a type/name format from full resource name.

    Args:
        full_resource_name (str): the full_resource_name of the resource

    Returns:
        str: type_name of that resource
    """

    return '/'.join(full_resource_name.split('/')[-2:])


def to_full_resource_name(full_parent_name, resource_type_name):
    """Creates a full resource name by parent full name and type name.

    Args:
        full_parent_name (str): the full_resource_name of the parent
        resource_type_name (str): the full_resource_name of the child

    Returns:
        str: full_resource_name of the child
    """
    # Strip out the fake composite root parent from the full resource name.
    if full_parent_name == 'composite_root/root/':
        return '{}/'.format(resource_type_name)

    return '{}{}/'.format(full_parent_name, resource_type_name)


def to_type_name(resource_type, resource_name):
    """Creates a type/name from type and name.

    Args:
        resource_type (str): the resource type
        resource_name (str): the resource name

    Returns:
        str: type_name of the resource
    """

    return '{}/{}'.format(resource_type, resource_name)


def split_type_name(resource_type_name):
    """Split the type name of the resource

    Args:
        resource_type_name (str): the type_name of the resource

    Returns:
        tuples: type and name of the resource
    """

    return resource_type_name.split('/')


def resource_to_type_name(resource):
    """Creates a type/name format from a resource dbo.

    Args:
        resource (object): the resource to get the the type_name

    Returns:
        str: type_name of the resource
    """

    return resource.type_name


def get_sql_dialect(session):
    """Return the active SqlAlchemy dialect.

    Args:
        session (object): the session to check for SqlAlchemy dialect

    Returns:
        str: name of the SqlAlchemy dialect
    """

    return session.bind.dialect.name


def get_resources_from_full_name(full_name):
    """Parse resource info from full name.

    Args:
        full_name (str): Full name of the resource in hierarchical format.
            Example of a full_name:
            organization/88888/project/myproject/firewall/99999/
            full_name has a trailing / that needs to be removed.


    Yields:
        iterator: strings of resource_type and resource_id
    """

    full_name_parts = full_name.split('/')[:-1]
    full_name_parts.reverse()
    resource_iter = iter(full_name_parts)
    for resource_id, resource_type in izip(resource_iter, resource_iter):
        yield resource_type, resource_id


def get_resource_id_from_type_name(type_name):
    """Returns the key from type_name.

    Args:
        type_name (str): Type name.

    Returns:
        str: Resource id.
    """
    if '/' in type_name:
        return type_name.split('/')[-1]
    return type_name
