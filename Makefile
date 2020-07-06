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

DEV_TOOLS_TAG := 0.7.5
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
.PHONY: docker_test_e2e_shell
docker_test_e2e_shell:
	docker run --rm -it \
		-e KITCHEN_TEST_BASE_PATH="/workspace/integration_tests/tests" \
		-e SERVICE_ACCOUNT_JSON \
		-e TF_VAR_billing_account \
		-e TF_VAR_domain \
		-e TF_VAR_forseti_email_recipient \
		-e TF_VAR_forseti_email_sender \
		-e TF_VAR_forseti_version \
		-e TF_VAR_gsuite_admin_email \
		-e TF_VAR_inventory_email_summary_enabled \
		-e TF_VAR_inventory_performance_cai_dump_paths \
		-e TF_VAR_kms_key \
		-e TF_VAR_kms_keyring \
		-e TF_VAR_org_id \
		-e TF_VAR_project_id \
		-e TF_VAR_sendgrid_api_key \
		-v $(CURDIR):/workspace \
		$(DEV_TOOLS_URL)/${DEV_TOOLS_IMAGE}:${DEV_TOOLS_TAG} \
		/bin/bash

# Execute terraform init for the end-to-end tests
.PHONY: docker_test_e2e_create
docker_test_e2e_create:
	docker run --rm -it \
		-e SERVICE_ACCOUNT_JSON \
		-v $(CURDIR):/workspace \
		--entrypoint /bin/bash \
		$(DEV_TOOLS_URL)/${DEV_TOOLS_IMAGE}:${DEV_TOOLS_TAG} \
		-c 'source /usr/local/bin/task_helper_functions.sh && kitchen_do create'

# Execute terraform apply for the end-to-end tests
.PHONY: docker_test_e2e_converge
docker_test_e2e_converge:
	docker run --rm -it \
		-e KITCHEN_TEST_BASE_PATH="/workspace/integration_tests/tests" \
		-e SERVICE_ACCOUNT_JSON \
		-e TF_VAR_billing_account \
		-e TF_VAR_domain \
		-e TF_VAR_forseti_email_recipient \
		-e TF_VAR_forseti_email_sender \
		-e TF_VAR_forseti_version \
		-e TF_VAR_gsuite_admin_email \
		-e TF_VAR_inventory_email_summary_enabled \
		-e TF_VAR_inventory_performance_cai_dump_paths \
		-e TF_VAR_kms_key \
		-e TF_VAR_kms_keyring \
		-e TF_VAR_org_id \
		-e TF_VAR_project_id \
		-e TF_VAR_sendgrid_api_key \
		-v $(CURDIR):/workspace \
		--entrypoint /bin/bash \
		$(DEV_TOOLS_URL)/${DEV_TOOLS_IMAGE}:${DEV_TOOLS_TAG} \
		-c 'source /usr/local/bin/task_helper_functions.sh && kitchen_do converge'

# Execute the end-to-end tests
.PHONY: docker_test_e2e_verify
docker_test_e2e_verify:
	docker run --rm -it \
		-e KITCHEN_TEST_BASE_PATH="/workspace/integration_tests/tests" \
		-e SERVICE_ACCOUNT_JSON \
		-v $(CURDIR):/workspace \
		--entrypoint /bin/bash \
		$(DEV_TOOLS_URL)/${DEV_TOOLS_IMAGE}:${DEV_TOOLS_TAG} \
		-c 'source /usr/local/bin/task_helper_functions.sh && kitchen_do verify'

# Execute terraform destroy for the end-to-end tests
.PHONY: docker_test_e2e_destroy
docker_test_e2e_destroy:
	docker run --rm -it \
		-e KITCHEN_TEST_BASE_PATH="/workspace/integration_tests/tests" \
		-e SERVICE_ACCOUNT_JSON \
		-v $(CURDIR):/workspace \
		--entrypoint /bin/bash \
		$(DEV_TOOLS_URL)/${DEV_TOOLS_IMAGE}:${DEV_TOOLS_TAG} \
		-c 'source /usr/local/bin/task_helper_functions.sh && kitchen_do destroy'
