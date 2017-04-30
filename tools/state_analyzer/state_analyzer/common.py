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

import functools


_unset = object()


class CachedProperty(object):
    """
    A variant of ``@property`` that caches the result of calling the
    decorated function.  It is not possible to have setters or getters
    on a ``CachedProperty`` object, as those are used to control the
    cache.
    """

    def __init__(self, func):
        """
        Initialize a ``CachedProperty`` instance.

        :param callable func: The function being decorated.  The
                              function will be called when a value has
                              not been cached.
        """

        # Save the function to call
        self.func = func

        # Where we will store the cached value on the instance
        self.attr = '_cached_property_%x' % id(self)

        # Update the wrapper
        functools.update_wrapper(self, func)

    def __get__(self, instance, owner):
        """
        Get the value of a cached property.

        :param instance: The instance of the class the cached property
                         is a member of.  May be ``None`` for access
                         via the class.
        :param owner: The class the cached property is a member of.

        :returns: If ``instance`` is ``None``, returns this object to
                  allow for introspection.  Otherwise, returns the
                  value of the cached property, possibly calling the
                  generating function if the value has not been
                  generated yet.
        """

        # Allow introspection
        if instance is None:
            return self

        # Try getting the value
        value = getattr(instance, self.attr, _unset)

        # Not set; call the function
        if value is _unset:
            value = self.func(instance)
            setattr(instance, self.attr, value)

        return value

    def __set__(self, instance, value):
        """
        Set the value of a cached property.  This method is provided to
        allow for testing.

        :param instance: The instance of the class the cached property
                         is a member of.
        :param value: The new value to place into the cache.
        """

        setattr(instance, self.attr, value)

    def __delete__(self, instance):
        """
        Clear the cached property value.  This may be used to clear the
        cache, forcing regeneration of the cached value.  It is
        acceptable to use ``del`` on a cached property regardless of
        whether the value has been cached.

        :param instance: The instance of the class the cached property
                         is a member of.
        """

        try:
            delattr(instance, self.attr)
        except AttributeError:
            pass


class Synthetic(Exception):
    """
    Raised when attempting to access the ``data`` property of
    synthetic states or transitions.  These elements are implicitly
    created for start states, and are of use only for the ``dot``
    property.
    """

    pass
