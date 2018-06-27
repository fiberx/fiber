#!/bin/bash

pip uninstall networkx
git clone https://github.com/networkx/networkx.git networkx
cd networkx
git pull
git checkout networkx-1.11
python setup.py install
cd ..
pip install fuzzywuzzy
#Should be ready to go.
echo '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'
echo 'Now you are using networkx v1.11 in current virtual env.'
