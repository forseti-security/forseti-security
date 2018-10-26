---
title: Instrumentation 
order: 200
---

# {{ page.title }}

OpenCensus tracing has been added to Forseti as part of instrumentation on 
Forseti. 

---

## Configuring Instrumentation

**Tracing**
* Tracing is enabled by default and the traces are automatically 
exported to `Stackdriver Trace`.
* If you wish to disable tracing, you may do so by modifying the 
`initialize_forseti_services.sh`script found under `install/gcp/scripts` to 
remove `FORSETI_COMMAND+=" --enable tracing"` and redeploy Forseti. 
* Tracing is done in a background thread.
* Traces are extremely helpful for latency analysis of gRPC calls.
* Stackdriver Exporter is the default exporter for traces.