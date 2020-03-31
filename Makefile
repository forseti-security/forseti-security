# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Make will use bash instead of sh
SHELL := /usr/bin/env bash

DEV_TOOLS_TAG := 0.4.1
DEV_TOOLS_IMAGE := cft/developer-tools
DEV_TOOLS_URL := gcr.io/cloud-foundation-cicd

FORSETI_NS := forseti-security
FORSETI_IMAGE_NAME := forseti-server
FORSETI_TEST_IMAGE_NAME := forseti-test
FORSETI_TAG := $(shell git rev-parse --short HEAD)
CONTAINER_NAME ?= forseti-server

LOG_LEVEL := info
SERVICES := 'explain inventory model scanner notifier'

# Build Forseti-server docker image
docker:
	docker build --target forseti-server -t $(FORSETI_NS)/$(FORSETI_IMAGE_NAME):$(FORSETI_TAG) .

# Rebuild Forseti-server docker image
docker_rebuild:
	docker build --no-cache --target forseti-server -t $(FORSETI_NS)/$(FORSETI_IMAGE_NAME):$(FORSETI_TAG) .

# Build Forseti-test docker image
docker_target_test:
	docker build --target forseti-test -t $(FORSETI_NS)/$(FORSETI_TEST_IMAGE_NAME):$(FORSETI_TAG) .

# Run Forseti docker image
.PHONY: docker_run
docker_run: docker
	docker-compose up

# Run flake8 style tests with docker
.PHONY: docker_test_lint_flake
docker_test_lint_flake: docker_target_test
	docker run -it --rm \
		--entrypoint /bin/bash \
		$(FORSETI_NS)/$(FORSETI_TEST_IMAGE_NAME):$(FORSETI_TAG) \
		-c "flake8 -v --doctests --max-line-length=80 --ignore=E501,E711,E722,F841,W504,W605 --exclude=*pb2*.py /home/forseti/forseti-security/google/"

# Run pylint tests with docker
.PHONY: docker_test_lint_pylint
docker_test_lint_pylint: docker_target_test
	docker run -it --rm \
		--entrypoint /bin/bash \
		$(FORSETI_NS)/$(FORSETI_TEST_IMAGE_NAME):$(FORSETI_TAG) \
		-c "pylint --rcfile=/home/forseti/forseti-security/pylintrc /home/forseti/forseti-security/google/ /home/forseti/forseti-security/install/"

# Run lint tests with docker
.PHONY: docker_test_lint
docker_test_lint: docker_target_test docker_test_lint_pylint docker_test_lint_flake

# Run unit tests with docker
.PHONY: docker_test_unit
docker_test_unit: docker_target_test
	docker run -it --rm \
		--entrypoint /bin/bash \
		$(FORSETI_NS)/$(FORSETI_TEST_IMAGE_NAME):$(FORSETI_TAG) \
 		-c "python3 -m unittest discover --verbose -s /home/forseti/forseti-security/tests/ -p '*_test.py'"

# Enter docker container for local development
.PHONY: docker_e2etest_shell
docker_e2etest_shell:
	docker run --rm -it \
		-e KITCHEN_TEST_BASE_PATH="~/git_repos/forseti-security/integration_tests/tests" \
		-e SERVICE_ACCOUNT_JSON \
		--env-file ~/forseti/environments/forseti-gce-fanta/travis-integration.env \
		-v $(CURDIR):/workspace \
		$(DEV_TOOLS_URL)/${DEV_TOOLS_IMAGE}:${DEV_TOOLS_TAG} \
		/bin/bash

# Execute terraform init for the end-to-end tests
.PHONY: e2etest_create
e2etest_create:
	kitchen create --test-base-path="integration_tests/tests"

# Execute terraform apply for the end-to-end tests
.PHONY: e2etest_converge
e2etest_converge:
	kitchen converge --test-base-path="integration_tests/tests"

# Execute the end-to-end tests
.PHONY: e2etest_verify
e2etest_verify:
	kitchen verify --test-base-path="integration_tests/tests"

# Execute terraform destroy for the end-to-end tests
.PHONY: e2etest_destroy
e2etest_destroy:
	kitchen destroy --test-base-path="integration_tests/tests"
