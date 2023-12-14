#!/bin/bash

wrokon python38
pip install -r requirement.txt
cd executor/validator/
python3 setup.py install
cd executor/searcher/
python3 setup.py install

