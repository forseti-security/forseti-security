#!/bin/bash

if [ -z "$DEVSHELL_PROJECT_ID" ]; then
  echo "ERROR: Project ID unknown - please restart cloudshell"
  exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR
terraform init
terraform apply -var gcp_project=$DEVSHELL_PROJECT_ID -auto-approve

# Turbinia
cd ~
virtualenv --python=/usr/bin/python2.7 turbinia
source turbinia/bin/activate
pip install turbinia
cd $DIR
terraform output turbinia-config > ~/.turbiniarc
sed -i s/"\/var\/log\/turbinia\/turbinia.log"/"\/tmp\/turbinia.log"/ ~/.turbiniarc

echo "Deployment done!"
terraform output
