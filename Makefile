# Copyright 2019 Google LLC
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
APP_NAME=forseti-security
SHELL := /usr/bin/env bash

DOCKER_TAG_VERSION_DEVELOPER_TOOLS := 0.4.6
DOCKER_IMAGE_DEVELOPER_TOOLS := cft/developer-tools
REGISTRY_URL := gcr.io/cloud-foundation-cicd

# grep the version from the mix file
VERSION=$(grep -o '[0-9].[0-9][0-9].[0-9]' google/cloud/forseti/__init__.py)

# docker build --target forseti-server -t gcr.io/$PROJECT_ID/forseti-server:master .
docker_server:
	docker build --target forseti-server -t forseti-server -t master .

# Run lint tests
# Ignored lint errors:
# E501: Is line too long and should be handled by pylint.
# E711: Comparison to None and should be handled by pylint.
# E722: Bare except, it's been deemed OK by this project in certain cases.
# F841: Assigned but unused variable becuase flake/pycodestyle doesn't ignore _.
# W504: Line break after binary operator; have warning for before.
# W605: Invalid escape sequence. Pylint can specify which lines to ignore, while Flake8 cannot. Ignore this warning for
#       Flake8, so it will be caught by Pylint instead.
docker_lint_test: docker_server
	docker exec -i build /bin/bash -c "pylint --rcfile=pylintrc google/ install/"
	docker exec -i build /bin/bash -c "flake8 -v --doctests --max-line-length=80 --ignore=E501,E711,E722,F841,W504,W605 --exclude=*pb2*.py google/"

# Run all tests: lint + unit
docker_test: docker_lint_test docker_unit_test

# Run unit tests
docker_unit_test: docker_server
	docker exec -i build /bin/bash -c "python3 -m unittest discover --verbose -s tests/ -p '*_test.py'"

# Enter docker container for local development
.PHONY: docker_e2etest_shell
docker_e2etest_shell:
	docker run --rm -it \
		-e KITCHEN_TEST_BASE_PATH="~/git_repos/forseti-security/integration_tests/tests" \
		-e SERVICE_ACCOUNT_JSON \
		--env-file ~/forseti/environments/forseti-gce-fanta/travis-integration.env \
		-v $(CURDIR):/workspace \
		$(REGISTRY_URL)/${DOCKER_IMAGE_DEVELOPER_TOOLS}:${DOCKER_TAG_VERSION_DEVELOPER_TOOLS} \
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
