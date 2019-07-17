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
* Foresti tracing is optional and is disabled by default. To enable tracing,
tracing dependencies (OpenCensus and google-cloud-trace) need to be installed.
Those optional dependencies can be installed by running:
   ```
   cd forseti-security  
   pip install opencensus==0.2.0  
   pip install google-cloud-trace==0.19.0    
   ```
gRPC flags have been added to enable/disable tracing from the Server VM.
* After installing the dependencies, tracing can be enabled by running:
    ```
    forseti server tracing enable
    ``` 
* Tracing mode can be retrieved by running:
    ```
    forseti server tracing get
    ``` 
* Tracing can be disabled by running:
    ```
    forseti server tracing disable
    ``` 
* Dependencies can be uninstalled by running:
    ```bash
    pip uninstall opencensus    
    pip uninstall google-cloud-trace
    ```

**Sampling**
* Forseti will trace 100% of requests by default.
* Sampling percentage will be made configurable in future releases.

**Exporters**
* Forseti will send traces using the StackdriverExporter by default, and are
viewable in GCP console.
* However OpenCensus supports variety of exporters such as Zipkin, Jaeger etc.
* Feel free to add support for the exporter of your choice in the meantime, and 
please contribute back!
