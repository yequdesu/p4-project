# Implementing a Control Plane using P4Runtime

## Introduction

Improvement of the tunnel forwarding and counters of switch interface.

The control plane has not installed the table entries for ipv4_forwarding, although the corresponding actions are defined in the P4 code.

All hosts in the topology can communicate with each other, and the number of packets passed by hosts H1, H2 and H3 can be counted in pairs. **The forwarding mode supports only tunnel forwarding. Switches will add the myTunnel header to an IP packet upon ingress to the network then remove the myTunnel header as the packet leaves to the network to an end host.** In addition, different tunnel ids are used in different directions. Therefore, different data transmission directions can be counted.

## How to run
Start to compile advanced_tunnel.p4 and start a Mininet instance with three switches (s1, s2, s3) configured in a triangle, each connected to one host (h1, h2, h3), and assign IPs of 10.0.1.1, 10.0.2.2, 10.0.3.3 to the respective hosts.
```
make
```
But the hosts cannot communicate with each other before pushing the rules. 
```
python3 mycontroller-triangle.py
```

