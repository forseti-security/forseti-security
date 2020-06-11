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

pip install turbinia 1>/dev/null
cd $DIR
terraform output turbinia-config > ~/.turbiniarc
sed -i s/"\/var\/log\/turbinia\/turbinia.log"/"\/tmp\/turbinia.log"/ ~/.turbiniarc

url="$(terraform output timesketch-server-url)"
user="$(terraform output timesketch-admin-username)"
pass="$(terraform output timesketch-admin-password)"

echo
echo "Waiting for Timesketch installation to finish. This may take a few minutes.."
echo
while true; do
  response="$(curl -k -o /dev/null --silent --head --write-out '%{http_code}' $url)"
  if [[ "${response}" -eq "302" ]]; then
    break
  fi
  sleep 3
done

echo "****************************************************************************"
echo "Timesketch server: ${url}"
echo "User: ${user}"
echo "Password: ${pass}"
echo "****************************************************************************"

echo
echo "Deployment done"
echo
