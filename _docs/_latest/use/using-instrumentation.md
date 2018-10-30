---
title: Instrumentation
order: 200
---

# {{ page.title }}

Opencensus tracing has been added to Forseti as part of instrumentation on 
Forseti.

---

**Tracing**
* Tracing is enabled by default and the traces are automatically exported to 
`Stackdriver Trace`, and viewable in GCP console.
* Traces are extremely helpful for latency analysis of gRPC calls. Viewing 
traces in GCP console will keep you informed about the time taken in ms to 
create an inventory and/or perform various operations on the model. This data 
is critical in analysing and debugging latency issues. 
* Stackdriver Exporter is the default exporter for traces. Feel free to add in 
support for the exporter of your choice as OpenCensus supports variety of 
exporters such as Zipkin, Jaeger and contribute back. 



