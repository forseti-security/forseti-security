#!/bin/bash

if [ -z "$DEVSHELL_PROJECT_ID" ]; then
  echo "ERROR: Project ID unknown - please restart cloudshell"
  exit 1
fi

SA_NAME="terraform"
SA_MEMBER="serviceAccount:$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"

# Create AppEngine app in order to activate datastore
gcloud app create --region=us-central

# Create service account
echo "Create servide account for Terraform"
gcloud iam service-accounts create "${SA_NAME}" --display-name "${SA_NAME}"

# Grant IAM roles to the service account
echo "Grant permissions on service account"
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/editor'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/compute.admin'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/cloudfunctions.admin'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/servicemanagement.admin'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/pubsub.admin'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/storage.admin'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/redis.admin'
gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/cloudsql.admin'

# Create and fetch the service account key
echo "Fetch and store service account key"
gcloud iam service-accounts keys create ~/key.json --iam-account "$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"
export GOOGLE_APPLICATION_CREDENTIALS=~/key.json


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
