#!/bin/bash

pylint .

mypy --check-untyped-defs src/*.py src/**/*.py 

python -m unittest discover src
