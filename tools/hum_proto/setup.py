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
            '0 = hum_proto.message:_protocol0',
            '1 = hum_proto.message:_protocol1',
            '2 = hum_proto.message:_protocol2',
            '3 = hum_proto.message:_protocol3',
        ],
        'hum_proto.msg': [
            # Protocol 0
            'connectionstate = hum_proto.message:ConnectionState',
            'requestconnectionstate = hum_proto.message:'
            'RequestConnectionState',
            'connectionerror = hum_proto.message:ConnectionError',

            # Protocol 1
            'pingreply = hum_proto.message:PingReply',
            'pingrequest = hum_proto.message:PingRequest',

            # Protocol 2
            'starttlserror = hum_proto.message:StartTLSError',
            'starttlsreply = hum_proto.message:StartTLSReply',
            'starttlsrequest = hum_proto.message:StartTLSRequest',

            # Protocol 3
            'saslerror = hum_proto.message:SASLError',
            'requestsaslmechanisms = hum_proto.message:RequestSASLMechanisms',
            'saslmechanisms = hum_proto.message:SASLMechanisms',
            'saslclientstep = hum_proto.message:SASLClientStep',
            'saslserverstep = hum_proto.message:SASLServerStep',
        ],
    },
)
