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

import collections

import pkg_resources

# Allows us to cache not-found entrypoints
_notfound = object()


class EntrypointDict(collections.Mapping):
    """
    Represent a ``setuptools`` entry point group as a dictionary.
    """

    def __init__(self, group):
        """
        Initialize an ``EntrypointDict`` instance.

        :param str group: The name of the entry point group.
        """

        # Save the group name
        self._group = group

        # Cache of the entrypoints we've found
        self._entries = {}

    def __len__(self):
        """
        Determine the number of entry points referenced so far.

        :returns: The number of found entry points.
        :rtype: ``int``
        """

        # Subtract out the _notfound entries
        return len(self._entries) - sum(1 for v in self._entries.values()
                                        if v is _notfound)

    def __getitem__(self, key):
        """
        Retrieve an entry point.

        :param key: The name of the entry point.  This need not be a
                    string, but it will be coerced to one to look up
                    an entry point.

        :returns: The entry point.

        :raises KeyError:
            The designated entry point does not exist.
        """

        # Look up the entry point if we don't have it in the cache
        if key not in self._entries:
            return self.__missing__(key)

        # We've looked it up but couldn't find it
        elif self._entries[key] is _notfound:
            raise KeyError(key)

        # Return the entry point
        return self._entries[key]

    def __iter__(self):
        """
        Iterate through all entry points so far discovered.

        :returns: An iterator that yields key names.
        """

        for key, value in self._entries.items():
            # Skip entries that weren't found
            if value is _notfound:
                continue

            yield key

    def __missing__(self, key):
        """
        Look up an entry point in the entry point group.  This method is
        called when the entry point has not already been resolved, and
        will cache the results of the lookup in the dictionary.

        :param key: The name of the entry point to look up.  This will
                    be coerced to a string in the call to
                    ``pkg_resources.iter_entry_points``.

        :returns: The designated entry point.

        :raises KeyError:
            The designated entry point does not exist.
        """

        # Find the first working entrypoint with the given name
        for ep in pkg_resources.iter_entry_points(self._group, str(key)):
            try:
                # Try to load it
                obj = ep.load()
            except (ImportError, AttributeError, pkg_resources.UnknownExtra):
                # Ignore expected errors
                continue

            # Cache it so we don't come here again
            self._entries[key] = obj

            return obj

        # Couldn't find the entrypoint
        self._entries[key] = _notfound
        raise KeyError(key)
