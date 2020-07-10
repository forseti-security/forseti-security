#!/bin/bash
# Copyright 2019 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Exit on any error.
set -e

# Default constants.
readonly BOOT_FINISHED_FILE="/var/lib/cloud/instance/boot-finished"
readonly STARTUP_FINISHED_FILE="/var/lib/cloud/instance/startup-script-finished"

# Redirect stdout and stderr to logfile.
exec > /var/log/terraform_provision.log
exec 2>&1

# Exit if the startup script has already been executed successfully.
if [[ -f "$${STARTUP_FINISHED_FILE}" ]]; then
  exit 0
fi

# Wait for cloud-init to finish all tasks.
until [[ -f "$${BOOT_FINISHED_FILE}" ]]; do
  sleep 1
done

# --- MAIN ---

# Install Elasticsearch.
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list
apt-get update
apt-get install -y openjdk-11-jre-headless
apt-get install -y elasticsearch

# Enable the GCE discovery plugin.
echo "y" | /usr/share/elasticsearch/bin/elasticsearch-plugin install discovery-gce

# Export hostname so we can set the node name to it.
echo "export HOSTNAME=\$(hostname -s)" >> /etc/default/elasticsearch

BOOTSTRAP_MASTER_NODE="$(hostname -s | sed s/'[0-9]$'/'0'/)"

# Configure Elasticsearch.
cat >> /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: ${cluster_name}
node.name: $${HOSTNAME}
cloud.gce.project_id: ${project}
cloud.gce.zone: ${zone}
discovery.zen.hosts_provider: gce
network.host: _gce_
cluster.initial_master_nodes: $${BOOTSTRAP_MASTER_NODE}
EOF

# More memory to Elasticsearch.
sed -i s/"-Xms1g"/"-Xms16g"/ /etc/elasticsearch/jvm.options
sed -i s/"-Xmx1g"/"-Xmx16g"/ /etc/elasticsearch/jvm.options

# Start Elasticsearch and enable at boot.
/bin/systemctl enable elasticsearch.service
/etc/init.d/elasticsearch start

# --- END MAIN ---

date > "$${STARTUP_FINISHED_FILE}"
echo "Startup script finished successfully"
