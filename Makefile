# Add src/python to PYTHONPATH so pylint can find the modules
export PYTHONPATH := $(PWD)/src/python:$(PYTHONPATH)

include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)
