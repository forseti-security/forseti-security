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
* The only step required to enable tracing is to pass `enable_tracing="true"`
to the Terraform module.
* Tracing can be disabled by passing the `enable_tracing="false"` to the 
Terraform module or not passing `enable_tracing` flag as Tracing is disabled by
default.
