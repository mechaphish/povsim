from distutils.core import setup
import subprocess

setup(
      name='povsim',
      version='0.01',
      packages=['povsim'],
      install_requires=[
            'angr',
            'tracer',
      ],
)
