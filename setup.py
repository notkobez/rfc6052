#!/usr/bin/env python3
"""
Setup script for RFC 6052 implementation.
"""

from setuptools import setup


# Read the README file
def read_long_description():
    with open('README.md', 'r', encoding='utf-8') as f:
        return f.read()

# Read version from __version__ variable in rfc6052.py


def get_version():
    with open('rfc6052.py', 'r') as f:
        for line in f:
            if line.startswith('__version__'):
                return line.split('=')[1].strip().strip('"\'')
    return '1.0.0'


setup(
    name='rfc6052',
    version=get_version(),
    author='Your Name',
    author_email='your.email@example.com',
    description='RFC 6052 IPv4/IPv6 address translation implementation',
    long_description=read_long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/rfc6052',
    project_urls={
        'Bug Tracker': 'https://github.com/yourusername/rfc6052/issues',
        'Documentation': 'https://github.com/yourusername/rfc6052#readme',
        'Source Code': 'https://github.com/yourusername/rfc6052',
        'RFC 6052': 'https://datatracker.ietf.org/doc/html/rfc6052',
    },
    py_modules=['rfc6052'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet',
        'Topic :: System :: Networking',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'rfc6052=rfc6052:main',
        ],
    },
    keywords='ipv6 ipv4 rfc6052 nat64 translation networking',
    license='MIT',
    include_package_data=True,
    zip_safe=True,
    test_suite='test_rfc6052',
)
