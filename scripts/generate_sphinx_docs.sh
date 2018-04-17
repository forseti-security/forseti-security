#!/bin/bash
# Copyright 2018 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
BUILD_FROM_BRANCH="${1:-master}"

worktree="$(mktemp -d)"
trap 'rm -rf "$worktree"' EXIT
echo $worktree
git --work-tree=$worktree checkout "${BUILD_FROM_BRANCH}" .
git add -u .
pushd $worktree
  ./setup/scripts/docker_setup_forseti.sh
popd
docker build \
  -t forseti/generate_sphinx_docs \
  -f scripts/docker/generate_sphinx_docs.Dockerfile ./scripts/docker

container_id="$(docker create forseti/generate_sphinx_docs)"
rm -rf _docs/_latest/develop/reference
docker cp \
  "${container_id}":/forseti-security/build/sphinx/html/. \
  _docs/_latest/develop/reference

sed -i '/<li><a href="sqlalchemy/d' \
  _docs/_latest/develop/reference/_modules/index.html
sed -i '/<li><a href="namedtuple_/d' index.html \
  _docs/_latest/develop/reference/_modules/index.html
# sed -ri 's/(\{% .+? %\})/\{% raw %\}\1\{% endraw %\}/' DESCRIPTION.html
find _docs/_latest/develop/reference/.eggs/ -type f -print0 | xargs -0 \
  sed -ri 's/(\{% .+? %\})/\{% raw %\}\1\{% endraw %\}/'
find _docs/_latest/develop/reference/.eggs/ -type f -print0 | xargs -0 \
  sed -ri 's/(\{\{ .+? \}\})/\{% raw %\}\1\{% endraw %\}/'
rm -rf \
   _docs/_latest/develop/reference/objects.inv

docker rm "${container_id}"
