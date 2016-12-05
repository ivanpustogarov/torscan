Tor relay connectivity probing tool
===================================

The Tor network is often considered as a fully connected graph. This is only an
approximation though: if no current users chose two relays as a part of their
circuits the relays stay disconnected.

(Last tested on Debin 8.6 (jessie).)
This tool allows one to to check if two Tor relays have a TLS connection 
(and determine if there are Tor circuits going throug these relays). It
is based on the feature of the Tor protocol called "Canonical connections". See
https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt, section 5.3.1.


This tool implements the technique described in the paper
"TorScan: Tracing Long-lived Connections and Differential Scanning Attacks" by
Alex Biryukov, Ivan Pustogarov, and Ralf Philipp Weinmann.
(https://www.freehaven.net/anonbib/papers/torscan-esorics2012.pdf)

Setup
===============

Firt you will need to compile some piece of cpp code, this is a fast version of
'xor' which is used in our Tor crypto implementation (this cpp code relies on
libboost and pyublas (ncluded)).

	$ sudo apt-get install python-m2crypto python-pyasn1 python-numpy libboost-dev python-dev libboost-python-dev
	$ cd torlib/xorcpp/pyublas
	$ ./configure.py
	$ make
	$ cd ../
	$ make
	$ cd ../../

Example
===============

Here is an example how to check if two relays are connected.
This will first download Tor relays information and create onion skins;
it will save this info in file 'netstate'.
Then we do the actual scan by calling './torscan.py' which will check
if the relay running at 69.195.146.214:443 is connected with the relay running
at 78.47.61.94:443.

	$ ./getconsensus.py     
	$ ./torscan.py -n netstate -t 78.47.61.94:443 69.195.146.214:443

This will print some debug info in the console. 
After the scan is finished, it will generate two files:

	1480730709.canonicalScan.69-195-146-214.443.errors
	1480730709.canonicalScan.69-195-146-214.443.log

69-195-146-214.433 is the router that we were scanning.
The errors file contains the copy of the console debug output.
The log file is the one you need, it will contains something like this:

	1480730709 : 78-47-61-94.443(4),

The first field is the timestamp of when the scan was started.
Codes in brackets (4) indicate the connections' status.
E.g. (4) means that there is an open TLS connections with relay at 78-47-61-94.443.

Result encoding
===============

	code 4 (as in the example above) indicates that relays are connected.
	codes from 5 to 16 indicate that there is not connection between the realays
	codes from 0 to 3 inidicate that the scan was not finished for this relay.

Assume you scanned router 69.195.146.214:443 for connectivity with the rest of
the network using the follwoing command:

	$ ./torscan.py -n netstate 69.195.146.214:443

A log file '1480730709.canonicalScan.69-195-146-214.443.log' will be generated with
the following content:

	1480733034 : 197-231-221-211.9001(4), ... ,85-214-68-105.9001(15),45-32-55-88.10068(3),

The first field (1480733034) is the timestamp of when the scan started.
This is followed by the list of Tor relays with corresponding connectivity codes. For example:

	'197-231-221-211.9001(4)' means that '69-195-146-214.443' is connected to 197-231-221-211.9001.
	'85-214-68-105.9001(15)' means that '69-195-146-214.443' is not connected to 85-214-68-105.9001.
	'45-32-55-88.10068(3)' means that we did not finish the scan for 45-32-55-88.10068.

See file torlib/torscantoolbox.py for the corresponding codes and exact Tor cells that
this tool receives

Files
=====

	getconsensus.py -- Script to download conesensus/router descriptors and compute onion skins
	torscan.py -- The main program
	torlib/ -- python modules which do all the job
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
