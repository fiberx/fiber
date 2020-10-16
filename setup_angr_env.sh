#!/bin/bash

# $1: the dir to hold the angr-dev environment
# $2: the virtual env name you want to set for the angr-dev

mkdir $1
cd $1
git clone https://github.com/fiberx/angr-dev-fiber.git angr-dev
git -C angr-dev pull
git -C angr-dev checkout fiber
cd angr-dev
# Checkout our modified angr components for FIBER.
git clone https://github.com/fiberx/angr-fiber.git angr
git clone https://github.com/fiberx/claripy-fiber.git claripy
git clone https://github.com/fiberx/cle-fiber.git cle
git clone https://github.com/fiberx/angr-management-fiber.git angr-management
git clone https://github.com/fiberx/angr-doc-fiber.git angr-doc
git clone https://github.com/fiberx/angrop-fiber.git angrop
git clone https://github.com/fiberx/angr-simuvex-fiber.git simuvex
git clone https://github.com/fiberx/angr-vex-fiber.git vex
git clone https://github.com/fiberx/angr-pyvex-fiber.git pyvex
git clone https://github.com/fiberx/archinfo-fiber.git archinfo
git clone https://github.com/fiberx/angr-ailment-fiber.git ailment
git -C angr checkout fiber
git -C angr pull
git -C claripy checkout fiber
git -C claripy pull
git -C cle checkout fiber
git -C cle pull
git -C angr-management checkout fiber
git -C angr-management pull
git -C angr-doc checkout fiber
git -C angr-doc pull
git -C angrop checkout fiber
git -C angrop pull
git -C simuvex checkout fiber
git -C simuvex pull
git -C vex checkout fiber
git -C vex pull
git -C pyvex checkout fiber
git -C pyvex pull
git -C archinfo checkout fiber
git -C archinfo pull
git -C ailment checkout fiber
git -C ailment pull
# Set up the angr-dev environment
# sudo pip install virtualenvwrapper
./setup.sh -i -E $2
cd ../..
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "You are ready to go."
echo "workon $2 : to switch virtual environment before running fiber scripts."
echo "deactivate : exit the virtual environment."
