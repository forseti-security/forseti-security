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

""" Database session handling for IAM Explain. """

from sqlalchemy.orm import sessionmaker


class ScopedSession(object):
    """A scoped session is automatically released."""

    def __init__(self, session, auto_commit=False):
        self.session = session
        self.auto_commit = auto_commit

    def __enter__(self):
        return self.session

    def __exit__(self, exc_type, value, traceback):
        try:
            if traceback is None and self.auto_commit:
                self.session.commit()
        finally:
            self.session.close()


class ScopedSessionMaker(object):
    """Wraps session maker to create scoped sessions."""

    def __init__(self, session_maker, auto_commit=False):
        self.sessionmaker = session_maker
        self.auto_commit = auto_commit

    def __call__(self, *args):
        return ScopedSession(self.sessionmaker(*args), self.auto_commit)


def create_scoped_sessionmaker(engine):
    """Creates a scoped session maker"""

    return ScopedSessionMaker(
        sessionmaker(
            bind=engine),
        auto_commit=True)
