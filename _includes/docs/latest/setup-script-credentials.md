Terraform uses an IAM Service Account to deploy and configure resources on behalf of the user.  The Service Account and required APIs can be setup automatically with a provided script on the 
[Forseti Terraform Github repository](https://github.com/forseti-security/terraform-google-forseti/blob/master/helpers/setup.sh). 
The Service account and required APIs can also be configured manually by following 
the instructions documented [here]({% link _docs/latest/setup/install/roles-and-required-apis.md %}). Alternatively, if you are an Org Admin, you can use your own credentials to install Forseti.

```bash
git clone --branch modulerelease521 --depth 1 https://github.com/forseti-security/terraform-google-forseti.git
```

```bash
cd terraform-google-forseti
```
