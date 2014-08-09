**Why not use ntop, libpcap or *shark or another packet tool?**

We would like to correlate the connection with the process and user that created it.

**Why not use LSOF? It shows processes?**

Yes, it does, but it only shows connections in progress.  Transients, for example a single outbound UDP datagram, will not be reported.

**How does this work and why is it a kernel module?**

It just ties into the connect(2) system call, writing info such as the caller's pid, destination address and family to readers of /dev/connwatch.  If there is a better way to do this, I'm all ears.

**How about SystemTap?**

To be investigated.  It looks heavy weight and general.

**Then what are all the scripty bits for?**

They keep track of rules and reporting. White lists are places you frequent and expect your applications to be contacting.  Some domain specific configuration language will tie regex on domains or IP to actions like ignore, log, report, etc.  TBD.
