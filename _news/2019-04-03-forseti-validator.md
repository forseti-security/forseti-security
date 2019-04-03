---
title: Forseti Config Validator Efforts
author: Alex Sung
---
Today, we would like to announce Forseti’s next venture into making your GCP environments 
safer with Forseti Config Validator (FCV), an infrastructure-as-code solution that enables 
cloud admins to keep their environment safe with guardrails against misconfigurations, while 
allowing their developers to move quickly. This helps protect the customer’s environment 
against misconfigurations that can violate compliance and security best practices.

How it works
- Cloud admins write compliance and security best practice constraints (as YAML files) once, 
and store them within the company’s own Git repo as a central source of truth
- Forseti ingests constraints and instantiates them as a new scanner to monitor for violations
- Terraform Validator reads the same constraints to check for violations before provisioning, preventing misconfigurations from happening. 

Cloud admins can get started with constraints by checking out the Policy Library public repo.

{% responsive_image path: images/news/2019-04-03-forseti-validator.png alt: "Forseti Validator Work Flow" %}

**Sample customer story**  
Chili Oregano is an online eCommerce retailer and has just moved to the infrastructure-as-code 
management. An admin from chili-oregano.com can set a Domain Restriction constraint on their 
IAM policies, which makes it so that anyone outside of the chili-oregano.com’ domain will not 
be given access through an IAM policy for resources that belong to the organization.  

This constraint is stored centrally in Chili Oregano’s own Git repo. Now when a developer tries 
to check in an IAM policy change through Terraform, it will be checked by the Terraform Validator 
to make sure that the policy doesn’t contain people from outside chili-oregano.com. Additionally 
Forseti will monitor the IAM policies in the entire organization on an ongoing basis and if it 
sees policies with members outside of chili-oregano.com it will flag it for security admins to review.  

**For developers**
Contributing developers may now build customized scanning policies by creating constraint 
templates, where the business logic is written in Rego, and open-source policy language. The 
constraint template includes the business logic for what is a violation. Cloud admins will only 
need to provide inputs into YAMLs in order to instantiate the constraint templates as a new 
constraint.  

**Get started today**
- Install or upgrade to Forseti v2.14
- Enable config validator scanner by
  - (Terraform) Set config_validator_enabled inside of the Forseti module to true.
  - (Regular Install) Enable config-validator scanner in the forseti_conf_server.yaml file.
- Checkout the [Policy Library](https://github.com/forseti-security/policy-library)
- Configure your first constraint
- And you are good to go!

Learn more with our full setup and user guide [here]().  

Please note that the Forseti Config Validator and Policy Library repositories are hosted at 
our new [Forseti Security Github Org](https://github.com/forseti-security). Don’t be confused! 
The main Forseti repository will be migrating to join the new Org in the next couple of weeks.

Read more about Validator and related tools on the [GCP blog]().
