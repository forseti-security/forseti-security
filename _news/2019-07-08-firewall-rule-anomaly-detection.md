---
title: Anomaly Detection Experiments on Firewall Rule in Forseti
author: Joe Cheuk
---

Among security professionals, one way to identify a breach or spurious entity is to detect 
anomalies and abnormalities in customer’ usage trend. Recently, we launched the 
“Forseti Intelligent Agents” experimental initiative to identify anomalies,  enable systems 
to take advantage of common user usage patterns, and identify other outlier data points. 
In this way, we hope to help security specialists for whom it’s otherwise cumbersome and 
time-consuming to manually flag these data points.

Anomaly detection is a classic and common solution implemented across multiple business domains. 
We tested several machine-learning (ML) techniques for use in anomaly detection, analyzing 
existing data that had been used to create firewall rules and identify outliers. The approach, 
the results of which you can find in this [whitepaper](https://cloud.google.com/solutions/partners/forseti-firewall-rules-anomalies), was experimental and based on static 
analysis.

Read more about the effort on the [Google Cloud security blog post](https://cloud.google.com/blog/products/ai-machine-learning/forseti-intelligent-agents-an-open-source-anomaly-detection-module).
