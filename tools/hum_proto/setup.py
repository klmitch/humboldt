#!/usr/bin/env python

import os
import sys

import setuptools


# Utility function to read the README file
def readfile(filename):
    with open(filename) as f:
        return f.read()


# Utility function to read requirements.txt files
def readreq(filename):
    result = []
    with open(filename) as f:
        for line in f:
            line = line.strip()

            # Process requirement file references
            if line.startswith('-r '):
                subfilename = line.split(None, 1)[-1].split('#', 1)[0].strip()
                if subfilename:
                    result += readreq(subfilename)
                continue

            # Strip out "-e" prefixes
            if line.startswith('-e '):
                line = line.split(None, 1)[-1]

            # Detect URLs in the line
            idx = line.find('#egg=')
            if idx >= 0:
                line = line[idx + 5:]

            # Strip off any comments
            line = line.split('#', 1)[0].strip()

            # Save the requirement
            if line:
                result.append(line.split('#', 1)[0].strip())

    return result


# Invoke setup
setuptools.setup(
    name='hum_proto',
    version='0.0.1',
    author='Kevin L. Mitchell',
    author_email='klmitch@mit.edu',
    url='https://github.com/klmitch/humboldt/tree/master/tools/hum_proto',
    description='Humboldt Protocol Analyzer',
    long_description=readfile('README.rst'),
    packages=setuptools.find_packages(exclude=['tests', 'tests.*']),
    install_requires=readreq('requirements.txt'),
    tests_require=readreq('test-requirements.txt'),
    entry_points={
        'console_scripts': [
            'hum_proto = hum_proto.main:main.console',
        ],
        'hum_proto.proto': [
            '0 = hum_proto.protocols.connection:_protocol0',
            '1 = hum_proto.protocols.ping:_protocol1',
            '2 = hum_proto.protocols.tls:_protocol2',
            '3 = hum_proto.protocols.sasl:_protocol3',
        ],
        'hum_proto.msg': [
            # Protocol 0
            'connectionstate = hum_proto.protocols.connection:ConnectionState',
            'requestconnectionstate = hum_proto.protocols.connection:'
            'RequestConnectionState',
            'connectionerror = hum_proto.protocols.connection:ConnectionError',

            # Protocol 1
            'pingreply = hum_proto.protocols.ping:PingReply',
            'pingrequest = hum_proto.protocols.ping:PingRequest',

            # Protocol 2
            'starttlserror = hum_proto.protocols.tls:StartTLSError',
            'starttlsreply = hum_proto.protocols.tls:StartTLSReply',
            'starttlsrequest = hum_proto.protocols.tls:StartTLSRequest',

            # Protocol 3
            'saslerror = hum_proto.protocols.sasl:SASLError',
            'requestsaslmechanisms = hum_proto.protocols.sasl:'
            'RequestSASLMechanisms',
            'saslmechanisms = hum_proto.protocols.sasl:SASLMechanisms',
            'saslclientstep = hum_proto.protocols.sasl:SASLClientStep',
            'saslserverstep = hum_proto.protocols.sasl:SASLServerStep',
        ],
    },
)
