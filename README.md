Intro
=====

Small C programme to detect Sonos devices on your network and provide their IP addresses. It's basically an ARP scanner which knows about Sonos OUIs.

Compiling
---------

* Clone the repository
* ```gcc -o sonos-detector sonos-detector.c```

Running
-------
```
./sonos-detector eth1
```

Where eth5 is the interface to the network on which the Sonos devices reside

A verbose debug mode also exists:

```
 ./sonos-detector -d eth1
```
