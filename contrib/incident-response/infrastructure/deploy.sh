#!/bin/bash

if [ -z "$DEVSHELL_PROJECT_ID" ]; then
  echo "ERROR: Project ID unknown - please restart cloudshell"
  exit 1
fi

TIMESKETCH="1"
if [[ "$*" == --no-timesketch ]]
then
  TIMESKETCH="0"
  echo "--no-timesketch found: Not deploying Timesketch."
fi

SA_NAME="terraform"
SA_MEMBER="serviceAccount:$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"

# Create AppEngine app in order to activate datastore
gcloud app create --region=us-central

# Create service account
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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

# Deploy cloud functions
gcloud -q services enable cloudfunctions.googleapis.com

# Deploying cloud functions is flaky. Retry until success.
while true; do
  num_functions="$(gcloud functions list | grep task | wc -l)"
  if [[ "${num_functions}" -eq "3" ]]; then
    echo "All Cloud Functions deployed"
    break
  fi
  gcloud -q functions deploy gettasks --source modules/turbinia/data/ --runtime nodejs8 --trigger-http --memory 256MB --timeout 60s
  gcloud -q functions deploy closetask --source modules/turbinia/data/ --runtime nodejs8 --trigger-http --memory 256MB --timeout 60s
  gcloud -q functions deploy closetasks --source modules/turbinia/data/ --runtime nodejs8 --trigger-http --memory 256MB --timeout 60s
done

# Create and fetch the service account key
echo "Fetch and store service account key"
gcloud iam service-accounts keys create ~/key.json --iam-account "$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"
export GOOGLE_APPLICATION_CREDENTIALS=~/key.json

# Run Terraform to setup the rest of the infrastructure
terraform init
if [ $TIMESKETCH -eq "1" ]
then
  terraform apply -var gcp_project=$DEVSHELL_PROJECT_ID -auto-approve
else
  terraform apply --target=module.turbinia -var gcp_project=$DEVSHELL_PROJECT_ID -auto-approve
fi

# Turbinia
cd ~
virtualenv --python=/usr/bin/python2.7 turbinia
source turbinia/bin/activate

pip install turbinia 1>/dev/null
cd $DIR
terraform output turbinia-config > ~/.turbiniarc
sed -i s/"\/var\/log\/turbinia\/turbinia.log"/"\/tmp\/turbinia.log"/ ~/.turbiniarc

if [ $TIMESKETCH -eq "1" ]
then
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
fi

echo
echo "Deployment done"
echo
