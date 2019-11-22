**Optional roles**

* `roles/compute.securityAdmin` (server)

    Users can grant the `roles/compute.securityAdmin` at the organization level in order to use the 
    [Forseti Enforcer]({% link _docs/latest/use/cli/enforcer.md %}) module.
    
    To grant this role, set variable `enable_write = true` in your Terraform `main.tf`.

* `roles/cloudprofiler.agent` (server)

    Users can grant the `roles/cloudprofiler.agent` at the project level in order to use 
    [Cloud Profiler]({% link _docs/latest/configure/cloud-profiler/index.md %}).
    
    To grant this role, set variable `cloud_profiler_enabled = true` in your Terraform `main.tf`.

