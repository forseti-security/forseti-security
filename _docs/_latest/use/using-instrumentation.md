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
`Stackdriver Trace`.
* Tracing is done in a background thread.
* Traces are extremely helpful for latency analysis of gRPC calls.
* Stackdriver Exporter is the default exporter for traces.
