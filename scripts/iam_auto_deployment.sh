#!/bin/bash
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

# Preparation
TRED='\e[91m'
TYELLOW='\e[93m'
TNC='\033[0m'
repodir="/home/$USER/forseti-security"

# Set Organization ID
echo -e "${TYELLOW}Setting up organization ID${TNC}"

orgs=$(gcloud organizations list --format=flattened \
	| grep "organizations/" | sed -e 's/^name: *organizations\///g')

if [ "$(echo "$orgs" | wc -l)" -gt "1" ]
then
	orgNotChoose=true
	while $orgNotChoose
	do
		echo "There are multiple organizations your account has access to:"
		echo "$orgs" | sed -e 's/^/    /g'
		echo "Choose one to deploy IAM Explain?"
		read REPLY
		if [[ $'\n'$orgs$'\n' == *$'\n'$REPLY$'\n'* ]]
		then
			ORGANIZATION_ID=$REPLY
			orgNotChoose=false
		else
			echo "The organization you choose doesn't exist. Please try again..."
		fi
	done
else
	echo "There is only one organization your account has access to:"
	echo "    $orgs"
	read -p "Shall we proceed? (y/n)" -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		ORGANIZATION_ID=$orgs
	else
		echo "Organization not confirmed"
		exit 1
	fi
fi

# Get project information
echo "Fetching project ID"

PROJECT_ID=$(gcloud info | grep "project: \[" | sed -e 's/^ *project: \[//' -e  's/\]$//g')

# Checking user authority
echo -e "${TYELLOW}Please make sure you have adequate permissions on GCP and GSuite in order to deploy IAM Explain ${TNC}"
read -p "Press any key to proceed" -n 1 -r
echo

# Checking billing of the project
echo -e "${TYELLOW}Checking if billing is enabled on this project${TNC}"
BillingNotConfirmed=true
while $BillingNotConfirmed
do
	BillingState=$(gcloud beta billing projects describe $PROJECT_ID | grep "billingEnabled: " | sed -e 's/^billingEnabled: //g')
	if [[ $BillingState == "true" ]]
	then
	echo "Billing is confirmed"
		BillingNotConfirmed=false
	else
		echo "In order to deploy IAM Explain, please enable billing on this project: "
		echo "    $PROJECT_ID"
		read -p "Press any key to proceed" -n 1 -r
		echo
	fi
done

# Get the email address of a gsuite administrator
adminNotChoose=true
while $adminNotChoose
do
	echo -e "Please type in the full ${TYELLOW}email address of a gsuite administrator${TNC}."\
	"IAM Explain Inventory will assume the administrator's authority"\
	"in order to enumerate users, groups and group membership:"
	read GSUITE_ADMINISTRATOR
	echo "Please verify the email address of the gsuite administrator:"
	echo "$GSUITE_ADMINISTRATOR"
	read -p "Is it correct? (y/n)" -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		adminNotChoose=false
	else
		echo "You chose not to use this email address as the gsuite administrator. Try again..."
	fi
done


# Enable API
echo -e "${TYELLOW}Enabling APIs${TNC}"
echo "Following APIs need to be enabled in this project to run IAM Explain:"
echo "    Admin SDK API: admin.googleapis.com"
echo "    AppEngine Admin API: appengine.googleapis.com"
echo "    Cloud Resource Manager API: cloudresourcemanager.googleapis.com"
echo "    Cloud SQL Admin API: sqladmin.googleapis.com"
echo "    Cloud SQL API: sql-component.googleapis.com"
echo "    Compute Engine API: compute.googleapis.com"
echo "    Deployment Manager API: deploymentmanager.googleapis.com"
echo "    Google Identity and Access Management (IAM) API: iam.googleapis.com"
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
	gcloud beta service-management enable iam.googleapis.com
else
	echo "API Enabling skipped, if you haven't enable them, you can do so in cloud console."
fi

# Creating Service Account
echo -e "${TYELLOW}Setting up service accounts${TNC}"
echo "Here are the existing service accounts within this project:"
gcloud iam service-accounts list
read -p $'Do you want to use a existing service account for \e[93mgcp resources and policies scraping\033[0m? (y/n)' -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Please type in the service account email address you want to use:"
	read SCRAPINGSA
	gcloud iam service-accounts describe $SCRAPINGSA ||
	{
		echo "The existence of "$SCRAPINGSA" cannot be verified"
		exit 1
	}
else
	echo "Please type in the service account name you want to create:"
	read scrapingname
	SCRAPINGSA=$(gcloud iam service-accounts create \
		$scrapingname \
		--display-name "scraping service account for IAM Explain" \
		--format flattened \
		| grep -- 'email:' | sed -e 's/^email: *//g') ||
	{
		echo "Creating "$SCRAPINGSA" failed"
		exit 1
	}
fi

read -p $'Do you want to use a existing service account for \e[93mgsuite crawling\033[0m? (y/n)' -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Please type in the service account email address you want to use:"
	read GSUITESA
	gcloud iam service-accounts describe $GSUITESA ||
	{ 
		echo "The existence of "$GSUITESA" cannot be verified"
		exit 1
	}
else
	echo "Please type in the service account name you want to create:"
	read gsuitename
	GSUITESA=$(gcloud iam service-accounts create \
		$gsuitename \
		--display-name "gsuite service account for IAM Explain" \
		--format flattened \
		| grep -- 'email:' | sed -e 's/^email: *//g') ||
	{
		echo "Creating "$GSUITESA" failed"
		exit 1
	}
fi

# Creating gsuite service account key
gcloud iam service-accounts keys create \
    ~/gsuite.json \
    --iam-account $GSUITESA

# Service Accounts role assignment
echo -e "${TYELLOW}Assigning roles to the gcp scraping service account${TNC}"
echo "Following roles need to be assigned to the gcp scraping service account"
echo "    $SCRAPINGSA"
echo "to run IAM Explain:"
echo "    - Organization level:"
echo "        - 'roles/browser',"
echo "        - 'roles/compute.networkViewer',"
echo "        - 'roles/iam.securityReviewer',"
echo "        - 'roles/appengine.appViewer',"
echo "        - 'roles/servicemanagement.quotaViewer',"
echo "        - 'roles/cloudsql.viewer',"
echo "        - 'roles/compute.securityAdmin',"
echo "        - 'roles/storage.admin',"
echo "    - Project level:"
echo "        - 'roles/cloudsql.client'"
read -p "Do you want to use the script to assign the roles? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/browser
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/compute.networkViewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/iam.securityReviewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/appengine.appViewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/servicemanagement.quotaViewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/cloudsql.viewer
	
	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/compute.securityAdmin

	gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/storage.admin
	
	gcloud projects add-iam-policy-binding $PROJECT_ID \
	 --member=serviceAccount:$SCRAPINGSA \
	 --role=roles/cloudsql.client
else
	echo "Roles assigning skipped, if you haven't done it, you can do so in cloud console."
fi

# Prepare the deployment template yaml file
echo "Customizing deployment template..."
cp $repodir/deployment-templates/deploy-explain.yaml.sample \
$repodir/deployment-templates/deploy-explain.yaml
sed -i -e 's/ORGANIZATION_ID/'$ORGANIZATION_ID'/g' \
$repodir/deployment-templates/deploy-explain.yaml
sed -i -e 's/YOUR_SERVICE_ACCOUNT/'$SCRAPINGSA'/g' \
$repodir/deployment-templates/deploy-explain.yaml
sed -i -e 's/GSUITE_ADMINISTRATOR/'$GSUITE_ADMINISTRATOR'/g' \
$repodir/deployment-templates/deploy-explain.yaml

#Choose deployment branch
echo -e "${TYELLOW}Choosing Github Branch${TNC}"
echo "By default, master branch of IAM Explain will be deployed."
read -p "Do you want to change to another one? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	branches=$( cd $repodir; git branch -r | grep -v " -> " | sed -e 's/^  origin\///g' )
	branchNotChoose=true
	while $branchNotChoose
	do
		echo "Here are all branches available:"
		echo "$branches" | sed -e 's/^/    /g'
		echo "Please specify which branch do you want to deploy:"
		read BRANCHNAME
		if [[ $'\n'$branches$'\n' == *$'\n'$BRANCHNAME$'\n'* ]]
		then
			branchNotChoose=false
		else
			echo "The branch you choose doesn't exists. Please try again..."
		fi
	done
else
	BRANCH="master"
fi
sed -i -e 's/BRANCHNAME/'$BRANCHNAME'/g' \
$repodir/deployment-templates/deploy-explain.yaml

# sql instance name
echo -e "${TYELLOW}Choosing SQL Instance name${TNC}"
timestamp=$(date --utc +%Ft%Tz | sed -e 's/:/-/g')
SQLINSTANCE="iam-explain-no-external-"$timestamp
echo "Do you want to use the generated sql instance name:"
echo "    $SQLINSTANCE"
read -p "for this deployment? (y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
	echo "Here are the existing sql instances in this project:"
	gcloud sql instances list
	echo "Choose a sql instance name that is not used above, please notice that recent deleted"\
		"sql instance can still occupy the name space, even though they are not shown above:"
	read SQLINSTANCE
fi
sed -i -e 's/ iam-explain-sql-instance/ '$SQLINSTANCE'/g' \
$repodir/deployment-templates/deploy-explain.yaml

# Deployment name
echo -e "${TYELLOW}Choosing deployment name${TNC}"
DEPLOYMENTNAME="iam-explain-"$timestamp
echo "Do you want to use the generated deployment name:"
echo "    $DEPLOYMENTNAME"
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
echo -e "${TYELLOW}Start to deploy${TNC}"
response=$(gcloud deployment-manager deployments create $DEPLOYMENTNAME \
	--config $repodir/deployment-templates/deploy-explain.yaml)\
|| exit 1
VMNAME=$(echo "$response" | grep " compute." | sed -e 's/ .*//g')
 
echo -e "${TYELLOW}Copy the gsuite service account key file${TNC}"
for (( TRIAL=1; TRIAL<=5; TRIAL++ ))
do
	if [[ $TRIAL != 1 ]]; then
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
		gcloud compute scp ~/gsuite.json \
			ubuntu@$VMNAME:/home/ubuntu/gsuite.json \
			--zone=us-central1-c &&
		{
			cpResponse="SUCCESS"
			break
		}
	done
	if [[ $cpResponse == "SUCCESS" ]]; then
		break
	fi
done
if [[ $cpResponse != "SUCCESS" ]]; then
	echo "Service account key copy failed."
	echo "Please try to manually copy ~/gsuite.json to /home/ubuntu/gsuite.json on your vm:"
	echo "    $VMNAME"
	exit 1
fi

# Ask to setup the gsuite service account
echo -e "${TRED}WE ARE NOT FINISHED YET${TNC}"
echo "Please complete the deployment by enabling GSuite google"\
"groups collection on your gsuite service account:"
echo -e "${TYELLOW}Enable Domain Wide Delegation at Cloud Platform Console:${TNC}"
echo "https://console.cloud.google.com/iam-admin/serviceaccounts/project?project="$PROJECT_ID"&organizationId="$ORGANIZATION_ID
echo "  1. Locate the service account to enable Domain-Wide Delegation"
echo -e "      ${TYELLOW}$GSUITESA${TNC}"
echo "  2. Select Edit and then the Enable G Suite Domain-wide Delegation checkbox. Save."
echo "  3. On the service account row, click View Client ID. On the Client"\
"ID for Service account client panel that appears, copy the Client ID value,"\
"which will be a large number."
read -p "Press any key to proceed" -n 1 -r
echo

echo -e "${TYELLOW}Enable the service account in your G Suite admin control panel.${TNC}"
echo "https://admin.google.com/ManageOauthClients"
echo "You must have the super admin role in admin.google.com to complete these steps:"
echo "  1. In the Client Name box, paste the Client ID you copied above."
echo "  2. In the One or More API Scopes box, paste the following scope:"
echo "        https://www.googleapis.com/auth/admin.directory.group.readonly, "
echo "        https://www.googleapis.com/auth/admin.directory.user.readonly"
echo "  3. Click Authorize"
read -p "Press any key to proceed" -n 1 -r
echo
echo "Now we have finished."
 