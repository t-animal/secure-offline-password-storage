#!/bin/bash

mypy --check-untyped-defs src/*.py src/**/*.py 

python -m unittest discover src
