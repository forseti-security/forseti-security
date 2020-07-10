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

# Generate random passwords session key.
readonly SECRET_KEY="$(openssl rand -hex 32)"

# Add Plaso repository.
add-apt-repository -y ppa:gift/stable

# Install dependencies.
apt-get update
apt-get install -y nginx python3-pip python3-psycopg2 python-plaso plaso-tools

# Install Google Cloud dependencies
pip3 install google-cloud-pubsub google-cloud-storage

# Install Timesketch from PyPi.
wget https://raw.githubusercontent.com/google/timesketch/master/requirements.txt
pip3 install -r requirements.txt
pip3 install https://github.com/google/timesketch/archive/master.zip

# Create default config.
mkdir /etc/timesketch
wget https://raw.githubusercontent.com/google/timesketch/master/data/timesketch.conf -O /etc/timesketch/timesketch.conf

# Set session key.
sed -i s/"SECRET_KEY = '<KEY_GOES_HERE>'"/"SECRET_KEY = '$${SECRET_KEY}'"/ /etc/timesketch/timesketch.conf

# Configure database password.
sed -i s/"<USERNAME>:<PASSWORD>@localhost\/timesketch"/"${postgresql_user}:${postgresql_password}@${postgresql_host}\/${postgresql_db_name}"/ /etc/timesketch/timesketch.conf

# What Elasticsearch server to use.
sed -i s/"ELASTIC_HOST = '127.0.0.1'"/"ELASTIC_HOST = '${elasticsearch_node}'"/ /etc/timesketch/timesketch.conf

# Enable upload.
sed -i s/"UPLOAD_ENABLED = False"/"UPLOAD_ENABLED = True"/ /etc/timesketch/timesketch.conf
sed -i s/"redis:\/\/127.0.0.1:6379"/"redis:\/\/${redis_host}:${redis_port}"/ /etc/timesketch/timesketch.conf


# Systemd configuration for Gunicorn.
cat > /etc/systemd/system/gunicorn.service <<EOF
[Unit]
Description=gunicorn daemon
Requires=gunicorn.socket
After=network.target

[Service]
PIDFile=/run/gunicorn/pid
User=www-data
Group=www-data
RuntimeDirectory=gunicorn
ExecStart=/usr/bin/env gunicorn --pid /run/gunicorn/timesketch.pid --timeout 120 --workers 1 --bind unix:/run/gunicorn/socket --access-logfile /var/log/gunicorn/access.log --error-logfile /var/log/gunicorn/error.log --log-level DEBUG timesketch.wsgi
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/gunicorn.socket <<EOF
[Unit]
Description=gunicorn socket

[Socket]
ListenStream=/run/gunicorn/socket

[Install]
WantedBy=sockets.target
EOF

cat > /etc/tmpfiles.d/gunicorn.conf <<EOF
d /run/gunicorn 0755 www-data www-data -
EOF
/bin/systemd-tmpfiles --create

# Create Gunicorn log dir.
if [[ ! -d /var/log/gunicorn/ ]]; then
    mkdir /var/log/gunicorn/
    chown www-data.www-data /var/log/gunicorn/
fi

# Configure NGINX.
cat > /etc/nginx/sites-available/timesketch <<EOF
server {
  listen 80;
  listen [::]:80;

  listen 443 ssl;
  ssl_certificate /etc/nginx/ssl/nginx.crt;
  ssl_certificate_key /etc/nginx/ssl/nginx.key;

  client_max_body_size 0;

  location / {
    proxy_pass http://unix:/run/gunicorn/socket;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }

  if (\$scheme != "https") {
    return 301 https://\$host\$request_uri;
  }
}
EOF

# Set our Nginx config as default.
ln -sf /etc/nginx/sites-available/timesketch /etc/nginx/sites-enabled/default

# Create self signed certificate for Nginx.
mkdir /etc/nginx/ssl
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=Example/L=Example/O=DExample/CN=example.com" -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt

# Create database tables.
tsctl add_user --username ${timesketch_admin_username} --password ${timesketch_admin_password}

# Enable upload.
cat > /etc/systemd/system/celery.service <<EOF
[Unit]
Description=Celery Service
After=network.target

[Service]
Type=forking
User=www-data
Group=www-data
EnvironmentFile=-/etc/celery.conf
WorkingDirectory=/var/lib/celery

ExecStart=/bin/sh -c '/usr/local/bin/celery multi start w1 -A timesketch.lib.tasks --pidfile=/var/run/celery/%n.pid --logfile=/var/log/celery/%n%I.log --loglevel=INFO'
ExecStop=/bin/sh -c '/usr/local/bin/celery multi stopwait w1 --pidfile=/var/run/celery/%n.pid'
ExecReload=/bin/sh -c '/usr/local/bin/celery multi restart w1 -A timesketch.lib.tasks --pidfile=/var/run/celery/%n.pid --logfile=/var/log/celery/%n%I.log --loglevel=INFO'

[Install]
WantedBy=multi-user.target
EOF

# Create Celery directories.
mkdir -p /var/{lib,log,run}/celery
chown www-data /var/{lib,log,run}/celery

# GCS importer
wget https://raw.githubusercontent.com/google/timesketch/master/contrib/gcs_importer.py -O /usr/local/bin/gcs-importer.py

cat > /etc/systemd/system/gcs-importer.service <<EOF
[Unit]
Description=Google Cloud Storage importer for Timesketch

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/gcs-importer.py --project ${gcp_project} --bucket turbinia-${infrastructure_id} --subscription gcs-subscription --output /tmp/

[Install]
WantedBy=multi-user.target
EOF

# Enable and start WSGI, Celery and NGINX servers.
/bin/systemctl daemon-reload
/bin/systemctl enable gunicorn.socket
/bin/systemctl restart gunicorn.socket
/bin/systemctl enable celery.service
/bin/systemctl restart celery.service
/bin/systemctl enable gcs-importer.service
/bin/systemctl restart gcs-importer.service
/bin/systemctl restart nginx

# --- END MAIN ---

date > "$${STARTUP_FINISHED_FILE}"
echo "Startup script finished successfully"
