## What is a Win32 platform?
Is a programming interface that allows developers to create applications for Windows OS.

## What is a socket?
A network socket is a software endpoint that lets two programs send and receive data across a network or on the same computer.
An internet socket is defined by a combination of a transport protocol (such as TCP or UDP), an IP address, and a port number.

## What is WinPcap?
WinPcap is an open source library for packet capture and network analysis for the Win32 platforms.

Most networking applications access the network through widely used operatin system primitives such as sockets.

It allows us capture raw packets, filter packets

## Polling vs Event-driven libpcap programming

polling -> 

event-based -> pcap_loop() -> will be call by the OS when packet arrives


## Questions to answers
// name of the device | portion of the packet to capture (65536 guarantees that the whole packet is captured)
In the method pcap_open_live(argv[1], 65536)

What happend if the packets is less than that length?

Which kind of packets it refers? all?

What is pcap_t *adhandle? 

What is struct tm *tm ?


For each packet that we received, it always come the ethernet frame, that is the first bytes that we will see, see the image of ethernet-frame.png to understand the fields, and know how many bytes do you need to read, the preambule you don't read it, I don't know why, but it begins in destination address, source address, so the first 12 bytes are that addressess, and the following 2 bytes are the type, so it says to us which kind of protocol follow (IP, TCP, UDP, etc)
