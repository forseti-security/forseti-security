---
title: Asset Inventory
author: Andrew Hoying
---
With the release of [asset inventory](https://www.google.com/url?q=https://cloud.google.com/blog/products/gcp/gain-insights-about-your-gcp-resources-with-asset-inventory&sa=D&source=hangouts&ust=1539109101901000&usg=AFQjCNGWNRSXziSyWifOvmUnu44CyDuI6Q), Google Cloud Platform now provides a
simplified API interface for pulling a snapshot of resources across your
organization. Forseti [v2.5.0](https://github.com/GoogleCloudPlatform/forseti-security/releases) now integrates the [Cloud Asset API](https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/reference/rest/) into the
existing [inventory](https://forsetisecurity.org/docs/v1.1/quickstarts/inventory/index.html) crawler for all supported cloud resources and policies.
This integration reduces the time to complete each inventory snapshot and
reduces API usage, allowing you to more frequently scan your organization
resources for potential violations.
