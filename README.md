Tor relay connectivity probing tool
===================================

The Tor network is often considered as a fully connected graph. This is only an
approximation though: if no current users chose two relays as a part of their
circuits the relays stay disconnected.

This tool allows one to to check if two Tor relays have a TLS connection. This
is base on the feature of the Tor protocol called "Canonical connection". See
https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt, section 5.3.1.
Last tested on Debin 8.6 (jessie).

This tool implements the technique described in the paper
"TorScan: Tracing Long-lived Connections and Differential Scanning Attacks" by
Alex Biryukov, Ivan Pustogarov, and Ralf Philipp Weinmann.
(https://www.freehaven.net/anonbib/papers/torscan-esorics2012.pdf)

Here is an example how to check if two relays are connected.
This will first download Tor relays information and create onion skins;
it will save this info in file 'netstate'.
The we do actual scan be calling ./torscan.py which will use check
if Tor relay running at 69.195.146.214:443 is connected with Tor relay running
at 78.47.61.94:443.

	$ ./getconsensus.py     
	$ ./torscan.py -n netstate -t 78.47.61.94:443 69.195.146.214:443

This will print some debug info in the console. 
After the scan is finished, it will generate two files:

	1480730709.canonicalScan.69-195-146-214.443.errors
        1480730709.canonicalScan.69-195-146-214.443.log

69-195-146-214.433 is the router that we were scanning
The errors file contains the copy of the console debug output.
The log file is the one you need, it will contains something like this:

	1480730709 : 78-47-61-94.443(4),

or like this:
	1480733034 : 197-231-221-211.9001(4), ... ,85-214-68-105.9001(15),45-32-55-88.10068(3),

The first field is the timestamp of when the scan was started.
Codes in brackets (4) indicate give the connections status.
E.g. (4) means that there is an open TLS connections with relay at 78-47-61-94.443.

Result encoding
===============

	code 4 (as in the example above) indicates that relays are connected.
	codes from 5 to 16 indicate that there is not connection between the realays
	codes from 0 to 3 inidicate that the scan was not finished for this relay.

See file torlib/torscantoolbox.py for the corresponding codes and exact Tor cells that
this tool receives

Files
=====

	getconsensus.py -- Script to download conesensus/router descriptors and compute onion skins
	torscan.py -- The main program
        torlib/ -- python modules which do all the job
          torlib/xorcpp.so -- 64-bit shared object which implements XOR 
          torlib/xorcpp/ -- the source code for xorcpp. You will need some dependencies to recompile it 
          torlib/pyubals -- pyublas 
	  ...
	router-list.example -- example of an input file with Tor relays
	LICENSE -- MIT licence

Dependencies
============
These are probably not all the dependencies:

	Python (>= 2.4)
	m2crypto (>= 0.20.1)
	pyasn1 (>= 0.0.11)
	hashlib (included in Python >= 2.5)


Other examples
==============

This will scan two relays from router-list.example and create two log files.

	./torscan.py -l 20 -n netstate -t 78.47.61.94:443 -f router-list.example
	 --> 1480733447.canonicalScan.78-47-61-94.443.log
	 --> 1480733447.canonicalScan.95-211-205-151.443.log


BC:14iyH71Y9kEDUXdQCytizPNTvFNAUUn3do 
