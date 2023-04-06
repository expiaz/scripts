#!/usr/bin/python3

import os, sys

cfg = """
from setuptools import setup, find_packages

setup(
	name='%s',
	packages=find_packages(),
	python_requires='>=3',
	scripts=['%s'],
	install_requires=[%s]
)
"""

with open(sys.argv[1], 'r') as reqs:
	with open('setup.py', 'w') as setup:
		app = os.path.basename(os.getcwd())
		setup.write(cfg % (
			app,
			sys.argv[2] if len(sys.argv) > 2 else '%s.py' % app,
			','.join(["'%s'" % l.strip() for l in reqs.readlines()])
		))

