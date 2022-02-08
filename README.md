# sysrepo-ietf-interfaces

Progress of YANG model implementation:

```
+--rw interfaces (config)
|  +--rw interface* [name]             Read-Only, populated from kernel
|     +--rw name                       Read-Only
|     +--rw description                RW
|     +--rw type                       Read-Only
|     +--rw enabled                    RW
|     +--rw link-up-down-trap-enable   NOT IMPLEMENTED, depends on if-mib yang model (SNMP)
+--ro interfaces (operational data)
 +--ro interface* [name]               Read-Only, populated from kernel
    +--ro name                         Read-Only
    +--ro type                         Read-Only
    +--ro admin-status                 NOT IMPLEMENTED, depends on if-mib yang model (SNMP)
    +--ro oper-status                  Read-Only
    +--ro last-change                  Read-Only
    +--ro if-index                     NOT IMPLEMENTED, depends on if-mib yang model (SNMP)
    +--ro phys-address                 Read-Only
    +--ro higher-layer-if*             Read-Only
    +--ro lower-layer-if*              Read-Only
    +--ro speed                        Read-Only
    +--ro statistics                  
       +--ro discontinuity-time        Read-Only
       +--ro in-octets                 Read-Only
       +--ro in-unicast-pkts           Read-Only
       +--ro in-broadcast-pkts         Read-Only
       +--ro in-multicast-pkts         Read-Only
       +--ro in-discards               Read-Only   
       +--ro in-errors                 Read-Only
       +--ro in-unknown-protos         Read-Only
       +--ro out-octets                Read-Only
       +--ro out-unicast-pkts          Read-Only
       +--ro out-broadcast-pkts        Read-Only   
       +--ro out-multicast-pkts        Read-Only
       +--ro out-discards              Read-Only
       +--ro out-errors                Read-Only
```

 
To make 'speed' attribute working need to setup rate estimator like:
`sudo tc qdisc add dev enp2s0 root estimator 1sec 8sec sfq perturb 10`
