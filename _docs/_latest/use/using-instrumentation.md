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
* Traces are extremely helpful for latency analysis of gRPC calls. For example,
viewing traces in GCP console will keep you informed about the time taken for 
operations between client and server to complete, such as to create an inventory
or data model. This is critical in analysing and debugging latency issues. 
* Stackdriver Exporter is the default exporter for traces, but OpenCensus 
supports variety of exporters such as Zipkin and Jaeger. Feel free to add 
support for the exporter of your choice, and please contribute back!
