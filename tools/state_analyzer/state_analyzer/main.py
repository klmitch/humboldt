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

import cli_tools

from state_analyzer import dot_util
from state_analyzer import yaml_util


@cli_tools.argument(
    'statefile',
    help='YAML file containing the Humboldt states.',
)
@cli_tools.argument(
    'outfile',
    help='Name of the file to which to write a canonical form of the '
    'Humboldt state YAML file.',
)
@cli_tools.argument(
    '--debug', '-d',
    action='store_true',
    help='Enable debugging mode.',
)
def canon(statefile, outfile):
    """
    Canonicalize a YAML file containing the Humboldt state
    descriptions.

    :param str statefile: The file to be canonicalized.
    :param str outfile: The name of the file to write the canonical
                        form to.  This may be the same as
                        ``statefile``.  The named file will be
                        overwritten.
    """

    # Read the states from the file
    state_list = yaml_util.from_file(statefile)

    # Write it to the selected output
    yaml_util.to_file(outfile, state_list)


@cli_tools.argument(
    'statefile',
    help='YAML file containing the Humboldt states.',
)
@cli_tools.argument(
    'outfile',
    help='Name of the file to which to write the visualization in the '
    'GraphViz format.',
)
@cli_tools.argument(
    '--debug', '-d',
    action='store_true',
    help='Enable debugging mode.',
)
def dot(statefile, outfile):
    """
    Generate a file in GraphViz format to visualize the state
    transitions contained within a file of Humboldt state
    descriptions.

    :param str statefile: The file to be read.
    :param str outfile: The name of the file to which the GraphViz
                        format will be written.
    """

    # Read the states from the file
    state_list = yaml_util.from_file(statefile)

    # Write dot to the selected output
    dot_util.to_file(outfile, state_list)
