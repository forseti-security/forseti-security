---
title: How to deploy Forseti without external IPs?
order: 1
---
{::options auto_ids="false" /}
Please follow the following steps to install Forseti with internal IP only:

* Prerequisites
    * Make sure the host subnet has [Google Private IP Access ](https://cloud.google.com/vpc/docs/configure-private-google-access) turned on.
    * Setup [Cloud NAT](https://cloud.google.com/nat/docs/using-nat) with a bastion host.
* Install Forseti
* Configure Cloud SQL
    * enable internal IP
    * remove the external IP
* Remove external IPs from the Forseti VMs
* Firewall Rules: Depending on how your environment is setup, you'll need to modify the firewall rules accordingly to allow SSH communication between the bastion host and Forseti VMs. A few suggestions:
    * Make sure the bastion host can access forseti VMs
    * Modify firewall rules created by Forseti installer limiting them to the subnet instead of 0.0.0.0/0
    * Limit Forseti egress to ports needed for pip and os updates

You are all set! To verify it works, access the forseti VMs by [connecting through a bastion host](https://cloud.google.com/compute/docs/instances/connecting-advanced#bastion_host).

A few common causes if you cannot access Forseti VMs from the bastion host:
* Your account does not have the appropriate permission
    * You might need to run:
        ```bash
        gcloud auth login
        ```
* Other firewall rules with higher priorities are blocking the SSH
* Your metadata is not configured properly
