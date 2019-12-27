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
SHELL := /usr/bin/env bash

DOCKER_TAG_VERSION_DEVELOPER_TOOLS := 0.4.1
DOCKER_IMAGE_DEVELOPER_TOOLS := cft/developer-tools
REGISTRY_URL := gcr.io/cloud-foundation-cicd

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
