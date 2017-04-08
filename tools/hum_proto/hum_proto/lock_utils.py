# Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

import abc
import threading

import six


@six.add_metaclass(abc.ABCMeta)
class RWInner(object):
    """
    Abstract base class for the reader or writer side of a read-write
    lock.
    """

    def __init__(self, lock):
        """
        Initialize a ``RWInner`` object.

        :param lock: The read-write lock's inner lock.
        :type lock: ``threading.Lock``
        """

        # Allocate the condition variable and initialize the counts
        self.cond = threading.Condition(lock)
        self.active = 0
        self.waiting = 0

    @abc.abstractmethod
    def predicate(self, other):
        """
        Predicate used for waiting on the read-write lock.

        :param other: The other ``RWInner`` object for the read-write
                      lock.
        :type other: ``RWInner``

        :returns: A ``True`` value if the read-write lock needs to
                  wait on other users, ``False`` otherwise.
        """

        pass  # pragma: no cover

    @abc.abstractmethod
    def signaler(self, other):
        """
        A signaler.  After a consumer releases the lock, this method is
        called to signal any waiters.

        :param other: The other ``RWInner`` object for the read-write
                      lock.
        :type other: ``RWInner``
        """

        pass  # pragma: no cover


class RWReader(RWInner):
    """
    A ``RWInner`` subclass for the reader side of a read-write lock.
    """

    def predicate(self, other):
        """
        Predicate used for waiting on the read-write lock.

        :param other: The other ``RWInner`` object for the read-write
                      lock.
        :type other: ``RWInner``

        :returns: A ``True`` value if the read-write lock needs to
                  wait on other users, ``False`` otherwise.
        """

        return other.active > 0

    def signaler(self, other):
        """
        A signaler.  After a consumer releases the lock, this method is
        called to signal any waiters.

        :param other: The other ``RWInner`` object for the read-write
                      lock.
        :type other: ``RWInner``
        """

        if self.active == 0 and other.waiting > 0:
            other.cond.notify()


class RWWriter(RWInner):
    """
    A ``RWInner`` subclass for the writer side of a read-write lock.
    """

    def predicate(self, other):
        """
        Predicate used for waiting on the read-write lock.

        :param other: The other ``RWInner`` object for the read-write
                      lock.
        :type other: ``RWInner``

        :returns: A ``True`` value if the read-write lock needs to
                  wait on other users, ``False`` otherwise.
        """

        return self.active > 0 or other.active > 0

    def signaler(self, other):
        """
        A signaler.  After a consumer releases the lock, this method is
        called to signal any waiters.

        :param other: The other ``RWInner`` object for the read-write
                      lock.
        :type other: ``RWInner``
        """

        if other.waiting > 0:
            other.cond.notify_all()
        elif self.waiting > 0:
            self.cond.notify()


class Locker(object):
    """
    The actual locker object.  Instances of this class are available
    via the ``read`` and ``write`` properties of a ``RWLock``
    instance, and perform the actual locking via the context manager
    protocol.
    """

    def __init__(self, lock, me, other):
        """
        Initialize a ``Locker`` instance.

        :param lock: The read-write lock's inner lock.
        :type lock: ``threading.Lock``
        :param me: The ``RWInner`` instance for this side of the lock.
        :type me: ``RWInner``
        :param other: The ``RWInner`` instance for the other side of
                      the lock.
        :type other: ``RWInner``
        """

        # Save the parameters
        self._lock = lock
        self._me = me
        self._other = other

    def __enter__(self):
        """
        Enter the context manager.

        :returns: This ``Locker`` instance.
        """

        with self._lock:
            # Do we need to wait?
            if self._me.predicate(self._other):
                # Signal that we're waiting
                self._me.waiting += 1

                # Wait until we can acquire the lock
                while self._me.predicate(self._other):
                    self._me.cond.wait()

                # We're not waiting anymore
                self._me.waiting -= 1

            # Keep track of how many are active
            self._me.active += 1

        return self

    def __exit__(self, _exc_value, _exc_type, _traceback):
        """
        Exit the context manager.

        :param _exc_value: The exception that was thrown, or ``None``.
                           Unused.
        :param _exc_type: The type of the exception that was thrown,
                          or ``None``.  Unused.
        :param _traceback: The traceback for the exception that was
                           thrown, or ``None``.  Unused.

        :returns: A ``None`` to indicate that the exception was not
                  handled.
        """

        with self._lock:
            # We're no longer active
            self._me.active -= 1

            # Notify any waiters
            self._me.signaler(self._other)

        return None


class RWLock(object):
    """
    A read-write lock object.  Use the ``read`` and ``write``
    properties, in conjunction with the ``with`` statement, to lock
    this object for reading or for writing.
    """

    def __init__(self):
        """
        Initialize a ``RWLock`` instance.
        """

        # Create the inner lock
        lock = threading.Lock()

        # Create the two sides of the lock
        self._read = RWReader(lock)
        self._write = RWWriter(lock)

        # Create the actual locker objects
        self._read_locker = Locker(lock, self._read, self._write)
        self._write_locker = Locker(lock, self._write, self._read)

    @property
    def read(self):
        """
        Obtain a context manager that will lock the read-write lock for
        reading.
        """

        return self._read_locker

    @property
    def write(self):
        """
        Obtain a context manager that will lock the read-write lock for
        writing.
        """

        return self._write_locker
