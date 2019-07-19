---
title: Instrumentation
order: 200
---

# {{ page.title }}

Starting from release v2.19.0, Forseti-Security integrates distributed tracing
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
* Foresti tracing is optional and is disabled by default. 
* Steps to enable tracing:
1. Install tracing dependencies (OpenCensus and google-cloud-trace) by running:
   ```
   cd forseti-security  
   pip install opencensus==0.2.0  
   pip install google-cloud-trace==0.19.0    
   ```
2. Set the environment variable by running:
    ```
    export FORSETI_ENABLE_TRACING=True
    ```
3. Restart the server by running:
    ```
    sudo systemctl restart forseti.service
    ```
Tracing is enabled and inventory can be created at this time. Forseti will send
traces using the StackdriverExporter by default, and are viewable in GCP console
under `Trace`.
* Tracing can be disabled at runtime by running:
    ```
    forseti server tracing disable
    ```
* If the tracing was disabled at runtime, it can be re-enabled by running:
    ```
    forseti server tracing enable
    ```
* Tracing mode at any time can be retrieved by running:
    ```
    forseti server tracing get
    ```
* Dependencies can be uninstalled by running:
    ```
    pip uninstall opencensus    
    pip uninstall google-cloud-trace
    ```
