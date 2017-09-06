#!/bin/sh
# Copyright 2017 The Forseti Security Authors. All rights reserved.
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


# Set Organization ID
echo "Setting up organization ID"

orgs=$(gcloud organizations list --format=flattened \
	| grep "organizations/" | sed -e 's/^name: *organizations\///g')

if [ "$(echo "$orgs" | wc -l)" -gt "1" ]
then
	echo "There are multiple organizations your account has access to:"
	echo "$orgs" | sed -e 's/^/    /g'
	orgs=$'\n'$orgs$'\n'
	echo "Choose one to deploy IAM Explain?"
	read REPLY
	match=$'\n'$REPLY$'\n'
	if [[ "$orgs" == *"$match"* ]]
	then
		ORGANIZATION_ID=$REPLY
	else
		echo "organization id not set"
		exit 1
	fi
else
	echo "There is only one organization your account has access to:"
	echo "    $orgs"
	read -p "Shall we proceed? (y/n)" -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		ORGANIZATION_ID=$orgs
	else
		echo "organization id not set"
		exit 1
	fi
fi

# Get project information
echo "Fetching project ID"

PROJECT_ID=$(gcloud info | grep "project: \[" | sed -e 's/^ *project: \[//' -e  's/\]$//g')

# Get the email address of a gsuite administrator
echo "Please type in the full email address of a gsuite administrator. \
IAM Explain Inventory will assume the administrator's authority \
in order to enumerate users, groups and group membership:"
read GSUITE_ADMINISTRATOR
echo "Please verify the email address of the gsuite administrator:"
echo "$GSUITE_ADMINISTRATOR"
read -p "Is it correct? (y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
	echo "Wrong email address of the gsuite administrator!"
	exit 1
fi

# Enable API
echo "Enabling APIs"
echo "Following APIs need to be enabled in this project to run IAM Explain:"
echo "    Admin SDK API: admin.googleapis.com"
echo "    AppEngine Admin API: appengine.googleapis.com"
echo "    Cloud Resource Manager API: cloudresourcemanager.googleapis.com"
echo "    Cloud SQL Admin API: sqladmin.googleapis.com"
echo "    Cloud SQL API: sql-component.googleapis.com"
echo "    Compute Engine API: compute.googleapis.com"
echo "    Deployment Manager API: deploymentmanager.googleapis.com"
read -p "Do you want to use the script to enable them? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	gcloud beta service-management enable admin.googleapis.com
	gcloud beta service-management enable appengine.googleapis.com
	gcloud beta service-management enable cloudresourcemanager.googleapis.com
	gcloud beta service-management enable sqladmin.googleapis.com
	gcloud beta service-management enable sql-component.googleapis.com
	gcloud beta service-management enable compute.googleapis.com
	gcloud beta service-management enable deploymentmanager.googleapis.com
else
	echo "API Enabling skipped, if you haven't enable them, you can done so in cloud console."
fi

# Creating Service Account
echo "Setting up service accounts"
echo "Here are the existing service accounts within this project:"
gcloud iam service-accounts list
read -p "Do you want to use a existing service account for gcp resources and policies scrapping? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Please type in the service account email address you want to use:"
	read SCRAPPINGSA
	resp=$(gcloud iam service-accounts describe $SCRAPPINGSA)
	if [[ -z $resp ]]
	then
		echo "The existence of "$SCRAPPINGSA" cannot be verified"
		exit 1
	fi
else
	echo "Please type in the service account name you want to create:"
	read scrappingname
	SCRAPPINGSA=$(gcloud iam service-accounts create \
		$scrappingname \
		--display-name "scrapping service account for IAM Explain" \
		--format flattened \
		| grep -- 'email:' | sed -e 's/^email: *//g')
	if [[ -z $SCRAPPINGSA ]]
	then
		echo "Creating "$SCRAPPINGSA" failed"
		exit 1
	fi
fi

read -p "Do you want to use a existing service account for gsuite crawling? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Please type in the service account email address you want to use:"
	read GSUITESA
	resp=$(gcloud iam service-accounts describe $GSUITESA)
	if [[ -z $resp ]]
	then
		echo "The existence of "$GSUITESA" cannot be verified"
		exit 1
	fi
else
	echo "Please type in the service account name you want to create:"
	read gsuitename
	GSUITESA=$(gcloud iam service-accounts create \
		$gsuitename \
		--display-name "gsuite service account for IAM Explain" \
		--format flattened \
		| grep -- 'email:' | sed -e 's/^email: *//g')
	if [[ -z $GSUITESA ]]
	then
		echo "Creating "$GSUITESA" failed"
		exit 1
	fi
fi

# Creating gsuite service account key
gcloud iam service-accounts keys create \
    ~/gsuite.json \
    --iam-account $GSUITESA

# Service Accounts role assignment
echo "Assigning roles to the gcp scrapping service account"
echo "Following roles need to be assigned to the gcp scrapping service account"
echo "$SCRAPPINGSA"
echo "to run IAM Explain:"
echo "    - Organization level:"
echo "        - 'roles/browser',"
echo "        - 'roles/iam.securityReviewer',"
echo "        - 'roles/appengine.appViewer',"
echo "        - 'roles/servicemanagement.quotaViewer',"
echo "        - 'roles/cloudsql.viewer',"
echo "        - 'roles/compute.securityAdmin',"
echo "    - Project level:"
echo "        - 'roles/cloudsql.client'"
read -p "Do you want to use the script to assign the roles? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/browser
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/compute.networkViewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/iam.securityReviewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/appengine.appViewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/servicemanagement.quotaViewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/cloudsql.viewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/compute.securityAdmin
	
	gcloud projects add-iam-policy-binding $PROJECT_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/storage.objectViewer
	
	gcloud projects add-iam-policy-binding $PROJECT_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/storage.objectCreator
	
	gcloud projects add-iam-policy-binding $PROJECT_ID \
	 --member=serviceAccount:$SCRAPPINGSA \
	 --role=roles/cloudsql.client
else
	echo "Roles assigning skipped, if you haven't done it, you can done so in cloud console."
fi

# Prepare the deployment template yaml file
cp ~/forseti-security/deployment-templates/deploy-explain.yaml.sample \
~/forseti-security/deployment-templates/deploy-explain.yaml
sed -i -e 's/ORGANIZATION_ID/'$ORGANIZATION_ID'/g' \
~/forseti-security/deployment-templates/deploy-explain.yaml
sed -i -e 's/YOUR_SERVICE_ACCOUNT/'$GSUITESA'/g' \
~/forseti-security/deployment-templates/deploy-explain.yaml
sed -i -e 's/GSUITE_ADMINISTRATOR/'$GSUITE_ADMINISTRATOR'/g' \
~/forseti-security/deployment-templates/deploy-explain.yaml

# sql instance name
timestamp=$(date --utc +%FT%TZ)
SQLINSTANCE="iam-explain-no-external-"$timestamp
echo "Do you want to use the generated sql instance name:"
echo "$SQLINSTANCE"
read -p "for this deployment? (y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
	echo "Here are the existing sql instances in this project:"
	gcloud sql instances list
	echo "Choose a sql instance name that is not used above, please notice that recent deleted \
		sql instance can still occupy the name space, even though they are not shown above:"
	read SQLINSTANCE
fi
sed -i -e 's/ iam-explain-sql-instance/ '$SQLINSTANCE'/g' \
~/forseti-security/deployment-templates/deploy-explain.yaml

DEPLOYMENTNAME="iam-explain-"$timestamp
echo "Do you want to use the generated deployment name:"
echo "$DEPLOYMENTNAME"
read -p "for this deployment? (y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
	echo "Here are existing deployments in this project:"
	gcloud deployment-manager deployments list
	echo "Choose a deployment name that is not used above"
	read DEPLOYMENTNAME
fi


# Deploy the IAM Explain
response=$(gcloud deployment-manager deployments create $DEPLOYMENTNAME \
	--config ~/forseti-security/deployment-templates/deploy-explain.yaml)
if [[ -z $response ]]; then
	exit 1
fi
VMNAME=$(echo "$response" | grep " compute." | sed -e 's/ .*//g')
 

for (( TRIAL=1; TRIAL<=5; TRIAL++ ))
do
	if [[ TRIAL !=1 ]]; then
		echo "Service account key copy not successful."
		read -p "Shall we keep trying? (y/n)" -n 1 -r
		echo
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			break
		fi
	fi
	for (( trial=1; trial<=10; trial++ ))
	do
		sleep 2
		response=$(gcloud compute scp ~/gsuite.json \
			ubuntu@$VMNAME:/home/ubuntu/gsuite.json \
			--zone=us-central1-c)
		if [[ -n $response ]]; then
			break
		fi
	done
	if [[ -n $response ]]; then
		break
	fi
done
if [[ -z $response ]]; then
	echo "Service account key copy failed."
	echo "Please try to manually copy ~/gsuite.json to /home/ubuntu/gsuite.json on your vm:"
	echo "$VMNAME"
	exit 1
fi


response=$(gcloud compute scp ~/gsuite.json \
	ubuntu@$VMNAME:/home/ubuntu/gsuite.json \
	--zone=us-central1-c)
if [[ -z $response ]]; then
	exit 1
fi

# Ask to setup the gsuite service account
echo "Please complete the deployment by enabling GSuite google \
groups collection on your gsuite service account:"
echo "$GSUITESA"
echo "with the manual on:"
echo "http://forsetisecurity.org/docs/howto/configure/gsuite-group-collection"
 
 
 
 
 
 
 
 
 
 
 
 
 