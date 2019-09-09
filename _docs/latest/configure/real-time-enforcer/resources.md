---
title: Resources
order: 501
---

# {{ page.title }}

For a list of the current resources and policies provided by Real-Time Enforcer, 
refer [here]({% link _docs/latest/configure/real-time-enforcer/default-policies.md %}).

## Excluding Resources

You can exclude specific resources by adding a label to the resource and adding the label’s `[KEY]:[VALUE]` 
pairing to the `config.yaml` file. In the example below, any resource with the `forseti-enforcer : disable` label 
will not be remediated by Real-Time Enforcer.

```
config:
  exclusions:
    labels:
      forseti-enforcer: disable
```

## For Developers

Real-Time Enforcer engine expects a fairly simple interface to any resource you wish to evaluate policy on. 
It expects an object with the following functions defined:

```
class MyResource:

    # Returns the body of a given resource as a dictionary
    def get(self):
        pass

    # Takes the body of a resource, and attempts to update the resource
    def update(self, body):
        pass
        
    # Returns the resource type as a string
    #  Note: This should be a dotted-string that the engines will use to determine what policies are relevant
    type(self):
        pass
       
```

