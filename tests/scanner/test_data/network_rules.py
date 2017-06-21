rules:
  - name: all pubs are in whitelist
    project: '*'
    network: '*'
    is_external_network: True
    whitelist:
      - xpn-master:xpn-network
      - content-insights:default