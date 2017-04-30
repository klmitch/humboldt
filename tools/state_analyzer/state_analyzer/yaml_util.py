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

import yaml

from state_analyzer import common
from state_analyzer import states


class StateAnalyzerDumper(yaml.Dumper):
    """
    Custom YAML ``Dumper`` class.  This provides a location to house
    our custom representers for Python sets and ordered dictionaries.
    """

    pass


def _set_representer(dumper, data):
    """
    Generate a YAML representation for Python ``set`` objects.  This
    converts a set into a sorted list of entries in flow style.

    :param dumper: A YAML dumper.
    :type dumper: ``yaml.Dumper``
    :param set data: The data to represent.

    :returns: A flow-style sequence node.
    :rtype: ``yaml.SequenceNode``
    """

    return dumper.represent_sequence(
        u'tag:yaml.org,2002:seq',
        sorted(data),
        flow_style=True,
    )
StateAnalyzerDumper.add_representer(set, _set_representer)


def _ordereddict_representer(dumper, data):
    """
    Generate a YAML representation for Python
    ``collections.OrderedDict`` objects.  This converts the ordered
    dictionary into a YAML mapping node, preserving the ordering of
    the dictionary.

    :param dumper: A YAML dumper.
    :type dumper: ``yaml.Dumper``
    :param data: The data to represent.
    :type data: ``collections.OrderedDictionary``

    :returns: A mapping node, with keys in the specified order.
    :rtype: ``yaml.MappingNode``
    """

    return yaml.MappingNode(
        u'tag:yaml.org,2002:map',
        [
            (dumper.represent_data(key), dumper.represent_data(value))
            for key, value in data.items()
        ]
    )
StateAnalyzerDumper.add_representer(
    collections.OrderedDict, _ordereddict_representer
)


def from_file(filename):
    """
    Loads a state transition data file, expressed in YAML format, and
    returns a list of the states from that file.

    :param str filename: The name of the file to load from.

    :returns: A list of states.
    :rtype: ``list`` of ``State``
    """

    with open(filename) as f:
        for state_desc in yaml.safe_load(f):
            state = states.HumboldtState(**state_desc)
            state.configure(**state_desc)

    # Return the list of loaded states, including synthetic StartState
    # instances
    return states.State.states()


def to_file(filename, state_list):
    """
    Saves a list of states to a state transition data file in YAML
    format.

    :param str filename: The name of the file to save to.
    :param state_list: The list of states to save to the file.
    :type state_list: ``list`` of ``State``
    """

    # Build the data first
    data = []
    for state in state_list:
        try:
            data.append(state.data)
        except common.Synthetic:
            # Ignore synthetic states
            pass

    # Write out the data
    with open(filename, 'w') as f:
        yaml.dump(data, f, StateAnalyzerDumper, default_flow_style=False)
