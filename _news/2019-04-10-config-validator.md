---
title: Forseti Config Validator Efforts
author: Alex Sung
---
Today we’re excited to announce Forseti Config Validator, the newest addition to the 
Forseti Security toolkit. Config Validator helps cloud admins put guardrails in place 
to protect against misconfigurations in Google Cloud Platform environments. This allows 
developers to move quickly, and gives security and governance teams the ability to 
enforce security at scale.

**How It Works**  
- Cloud admins write security and governance constraints (as YAML files) once, and store them 
within their company’s dedicated Git repo as a central source of truth  
- Forseti ingests constraints and uses them as a new scanner to monitor for violations  
- Terraform Validator reads the same constraints to check for violations before provisioning, 
in order to help prevent misconfigurations from happening  

Cloud admins can get started putting constraints in place by checking out the 
[Policy Library repo](https://github.com/forseti-security/policy-library).

{% responsive_image path: images/news/2019-04-10-config-validator.png alt: "Forseti Validator Work Flow" %}

**Sample Customer Story**  
Chili Oregano is an online eCommerce retailer. An admin from chili-oregano.com can set a Domain 
Restriction constraint on their IAM policies, which ensures that anyone outside of the 
chili-oregano.com domain will not be given access to resources that belong to the Chili Oregano 
organization.   

This constraint is stored centrally in Chili Oregano’s dedicatedGit repo. Now when a developer 
tries to check-in an IAM policy change through Terraform, it will be checked by the Terraform 
Validator to make sure that the policy doesn’t contain people from outside chili-oregano.com. 
Additionally Forseti will monitor the IAM policies in the entire organization on an ongoing basis. 
If it detects policies with members outside of chili-oregano.com it will flag it for security 
admins to review.  

**For Developers**  
Contributing developers may now build customized scanning policies by creating constraint
templates, where the business logic is written in Rego, and open-source policy language. The
constraint template includes the business logic for what is a violation. Cloud admins will only
need to provide inputs into YAMLs in order to instantiate the constraint templates as a new
constraint. 

**Get Started Today**  
- Install or upgrade to Forseti v2.14
- Enable config validator scanner by
 - (Terraform) Set config_validator_enabled inside of the Forseti module to true.
 - (Regular Install) Enable config-validator scanner in the forseti_conf_server.yaml file.
- Checkout the [Policy Library](https://github.com/forseti-security/policy-library)
- Configure your first constraint
- And you are good to go!

Read the details in our [User Guide](https://www.google.com/url?q=https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md).

Please note that the [Forseti Config Validator](https://github.com/forseti-security/config-validator) and 
[Policy Library](https://github.com/forseti-security/policy-library) repositories are hosted at our new 
[Forseti Security Github Org](https://github.com/forseti-security). Don’t worry! The main Forseti repository 
will be migrating to join the new Org in the next couple of weeks.  

Read more about Validator and related tools on the [Google Cloud Next ‘19 security blog post](https://cloud.google.com/blog/products/identity-security/increasing-trust-in-google-cloud-visibility-control-and-automation).
