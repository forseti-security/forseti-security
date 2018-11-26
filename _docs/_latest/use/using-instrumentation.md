---
title: Instrumentation
order: 200
---

# {{ page.title }}

Starting from release v2.9.0, Forseti-Security integrates distributed tracing
through the OpenCensus Python library.

---

OpenCensus is the open-source version of Census, the library used for at Google
to instrument applications (tracing, monitoring, etc.). 

OpenCensus provides distributed tracing for gRPC calls to Forseti. This will
prove very useful to observe application performance in order to optimize
Forseti's code.

**Tracing**
* Traces are extremely helpful for latency analysis of gRPC calls. For example,
viewing traces in GCP console will keep you informed about the time taken for 
operations between client and server to complete, such as to create an inventory
or data model. This is critical in analysing and debugging latency issues. 
* Foresti tracing is optional and is enabled by default in our automated
deployment with a CLI flag `--enable-tracing` set to `True`. It can be
toggled on/off by setting `enable-tracing` to `True/False` and 
running/re-running the automation.
* Tracing dependencies(OpenCensus and google-cloud-trace) are optional. 
(i.e we can install the forseti-security package without those dependencies).
Those optional dependencies can be installed by running:
   ```
   cd forseti-security
   pip install .[tracing]  
   ```
  However it's already installed if you're deploying Forseti using 
Deployment Manager.

  Note: Just running `pip install forseti-security` does not install the 
tracing libraries.
Tracing libraries (OpenCensus, google-cloud-trace, etc.) are optional 
(i.e we can install the forseti-security package without those dependencies).
* On a running Forseti VM, to disable tracing, follow the instructions steps:
1. SSH to the Forseti Server VM
    ```
    gcloud compute ssh <USER>@<FORSETI_VM_NAME>
	--project=<FORSETI_PROJECT> 
	--zone=<FORSETI_VM_ZONE>
   ```
1. Edit the Forseti init script.
   ```
   sudo vi /lib/systemd/forseti.service
   ```
1. Remove the `--enable-tracing` flag.
1. Reload the systemctl daemon by running:
   ```
   sudo systemctl daemon-reload
   ```
1. Restart Forseti service by running:
   ```
   sudo systemctl restart forseti.service
   ```

**Sampling**
* Forseti will trace 100% of requests by default.
* Sampling percentage will be made configurable in future releases.

**Exporters**
* Forseti will send traces using the StackdriverExporter by default, and are
viewable in GCP console.
* However OpenCensus supports variety of exporters such as Zipkin, Jaeger etc.
* Support for other exporters will be added in the future. Feel free to add 
support for the exporter of your choice in the meantime, and please contribute back!
* You can disable the Stackdriver Trace Exporter (default) by uninstalling the GCP 
tracing libraries: `pip install google-cloud-trace`. A FileExporter will be used
that exports traces by default to `/home/ubuntu/opencensus-traces.json`.