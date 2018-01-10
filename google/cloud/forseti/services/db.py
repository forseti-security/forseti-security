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

"""Database session handling for Forseti Server."""

from sqlalchemy.orm import sessionmaker


class ScopedSession(object):
    """A scoped session is automatically released."""

    def __init__(self, session, auto_commit=False):
        """Constructor.

        Args:
            session (object): Database session to use scope.
            auto_commit (bool): Set to true, if commit should automatically
                                happen upon close.
        """

        self.session = session
        self.auto_commit = auto_commit

    def __enter__(self):
        """To support with statement.

        Returns:
            object: Returns its session.
        """

        return self.session

    def __exit__(self, exc_type, value, traceback):
        """To support with statement.

        Args:
            exc_type (object): Exception type
            value (object): Exception value
            traceback (object): Traceback if any
        """
        try:
            if traceback is None and self.auto_commit:
                self.session.commit()
        finally:
            self.session.close()


class ScopedSessionMaker(object):
    """Wraps session maker to create scoped sessions."""

    def __init__(self, session_maker, auto_commit=False):
        """Constructor.

        Args:
            session_maker (object): Session creator.
            auto_commit (bool): If set to true, generated sessions will
                                automatically commit the transaction upon close
        """
        self.sessionmaker = session_maker
        self.auto_commit = auto_commit

    def __call__(self, *args):
        """Creates a new session.

        Args:
            *args (list): Will be forwarded to session creator.

        Returns:
            object: Scoped session.
        """

        return ScopedSession(self.sessionmaker(*args), self.auto_commit)


def create_scoped_sessionmaker(engine):
    """Creates a scoped session maker

    Args:
        engine (object): Engine to bind session to.

    Returns:
        object: Scoped session maker.
    """

    return ScopedSessionMaker(
        sessionmaker(
            bind=engine),
        auto_commit=True)
