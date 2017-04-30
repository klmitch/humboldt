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

from __future__ import print_function


def to_file(filename, state_list):
    """
    Saves the state transition diagram as GraphViz data, in the "dot"
    language.

    :param str filename: The name of the file to save to.
    :param state_list: The list of states to save to the file.
    :type state_list: ``list`` of ``State``
    """

    # Lists of GraphViz nodes and edges
    nodes = []
    edges = []

    # Create the elements of the graphic
    for state in state_list:
        nodes.append(state.dot)

        # Hit all that state's transitions
        for transition in state.transitions:
            edges.append(transition.dot)

    # Now we can create the file
    with open(filename, 'w') as f:
        print('digraph "states" {', file=f)
        print('\trankdir=LR;', file=f)
        print('\n\t%s' % '\n\t'.join(nodes), file=f)
        print('\n\t%s' % '\n\t'.join(edges), file=f)
        print('}', file=f)
