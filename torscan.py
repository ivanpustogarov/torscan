#! /usr/bin/python

# Copyright (c) 2014-2015 Ivan Pustogarov
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# -*- coding: utf-8 -*-
"""
Created on Thu Nov 17 11:51:41 2011

This script does connectivity probing of a Tor relay based on canonical
connections feature. It scans a tor router (for which ip and port are
provided) for connections with those routers

Note: When you do a long scan (for more than an hour), it is up to
you to update the tor_net_state.

@author: pustogarov
"""    

import getopt
import sys,os
from torlib.torscantoolbox import scan_torrouter,getGuardsFromRouterList,OR_Circuit,wait_nonmain_threads_dead
from torlib.torcrawl import TorException
from torlib import tordirinfo
import threading
from time import time,sleep,strftime,gmtime
import M2Crypto
import cProfile
import random
import copy
import traceback
import signal

TOR_NET_STATE_LAST_UPDATE = -1
tor_net_state_file_lock = threading.Lock()

class configParams:
    routers_to_scan_filename = None
    routers_to_scan  = list()
    netstate_filename = None
    max_scan_time  = 180        # In seconds
    delay_between_scans  = 200  # In seconds
    config_filename  = None
    scan_guards_only = False
    scan_target_ip = None
    scan_target_port = 0
    times_to_scan = None

def terminate_threads():
    ev.set()

def signal_handler(signal, frame):
    print "Received CTRL-C. Notifying threads."
    terminate_threads()

def wait_fo_signal():
    signal.signal(signal.SIGINT, signal_handler)
    


def print_usage_and_exit():
    print """Usage: 
                (1) torscan [OPTIONS] -n NETSTATE -t TARGET_IP:PORT TORIP:PORT 
                (2) torscan [OPTIONS] -n NETSTATE TORIP:PORT
                (3) torscan [OPTIONS] -n NETSTATE -f FILE_WITH_RELAYS 

	     The first form checks if relay at TORIP is connected to relays at TARGET_IP
	     The second form checks TORIP for connectivity with the rest of the network
	     The thrid form checks each of the relays found in file FILE_WITH_RELAYS for
	         connectivity with the rest of the network

             Scan Tor relay and discover to which other relay it is connected.
	     It uses "canonical connections" artefact.

	     Options:
	         -n FILE
		 		Network status file (geneate it using getconsensus.py)

	         -f FILE, --RoutersToScanFilename FILE
		                scan a bunch of relays whose IP addresses are in FILE  

		 -t TARGET_IP:PORT, --target TARGET_IP:PORT
		                check connectivity to this router

		 -l MAX_TIME, --MaxScanTime MAX_TIME
		                do scanning no longer then MAX_TIME in seconds.
		                By default there is not time limit and scan goes until the relay is fully scannned.

	         -d DELAY, --DelayBetweenScans DELAY
		                When chcking if A is connected with B, C, and D, make a paus of DELAY seconds
				between scans in order to reduce network load

		 -c CONFIG_FILE, --ConfigFilename CONFIG_FILE
		                read options from file CONFIG_FILE

		 -g, --ScanGuardsOnly
		                scan Guard nodes 

		 -h, --help
		                print this help message and exit
           """


    print "Example: "
    print "        ./getconsensus.py"
    print "        ./torscan.py -l 20 -n netstate -t 78.47.61.94:443 69.195.146.214:443"
    print "        ./torscan.py -l 20 -n netstate 69.195.146.214:443"
    exit()
    

def fillWithRoutersToScan(routers_to_scan_list,filename):
    fd = open(filename,"rt")
    if fd == None:
        print "Could not open file with routers to scan!"
        exit()
    line = fd.readline()
    while line:
        if len(line) > 3: #magic number to check whether this is just a new line without ip and port
            routers_to_scan_list.append(line.strip("\n"))
        line = fd.readline()
    fd.close()
    

def parseCommandLineParameters(params):
    args = sys.argv[1:]
    try:
        opts, args = getopt.getopt(args, "hn:f:t:d:l:", ["RoutersToScanFilename=","MaxScanTime=", "DelayBetweenScans=", "ConfigFilename=", "help"])
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
	print_usage_and_exit()
    for o, a in opts:
        if o in ("-h", "--help"):
	    print_usage_and_exit()
        elif o in ("-n"):
            configParams.netstate_filename = a
        elif o in ("-f","--RoutersToScanFilename"):
            configParams.routers_to_scan_filename = a
            fillWithRoutersToScan(configParams.routers_to_scan,configParams.routers_to_scan_filename)
        elif o in("-l","--MaxScanTime"):
            configParams.max_scan_time = float(a)
        elif o in("-t", "--target"):
            tokens = a.split(":")
	    if(len(tokens) != 2):
	       print "Wrong format for {} (should be IP:PORT).".format(r)
	       exit(0)
            configParams.scan_target_ip = a.split(":")[0]
            configParams.scan_target_port = int(a.split(":")[1])

        elif o in("-d","--DelayBetweenScans"):
            configParams.delay_between_scans = int(a)
        else:
            assert False, "unhandled option"

    if(len(args) != 0):
        configParams.routers_to_scan.append(args[0])

    if configParams.netstate_filename == None:
        print "Network state file is required (-n)"
	print "Use './torscan -h' for help"
	exit(0)

    if len(configParams.routers_to_scan) == 0:
        print "No routers to scan were specified!"
	print "Use './torscan -h' for help"
	exit(0)
        


# Note that all threads will share tor_net_state
def ScanRouter(ip_address_to_scan,port_to_scan, _routers_list, should_be_uptodate_tornetstate = False):
    global TOR_NET_STATE_LAST_UPDATE
    errmsg = threading.currentThread().name
    routers_list = copy.copy(_routers_list)
    orconns_log_filename = str(int(time()))+".canonicalScan.{0}.{1}.log".format(ip_address_to_scan.replace('.','-'),port_to_scan) 
    orconns_errors_filename = str(int(time()))+".canonicalScan.{0}.{1}.errors".format(ip_address_to_scan.replace('.','-'),port_to_scan)
    
    logs_fd = open(orconns_log_filename,"wt")
    
    errors_fd = open(orconns_errors_filename,"wt")
    
    prev_time = time()
    current_time = time()
    
    caught_exception = False
    
    tor_control_port = None
    #Start infine loop of scans

    scan_num = 1
    tor_net_state_file_lock.acquire()

    routers_list = copy.copy(_routers_list)
    tor_net_state_file_lock.release()
    tordirinfo.sortRouterListByBandwidth(routers_list)
    
    start_scan_time = time()
    caught_exception = False
    
    try:
        print "{0}: {1} : Starting scan {5} of {2}:{3}! We are going to stop when {4} secs elapsed... ".format(threading.currentThread().name,start_scan_time, ip_address_to_scan, port_to_scan,configParams.max_scan_time,scan_num)
        errors_fd.write("{0}: {1} : Starting scan {5} of {2}:{3}! We are going to stop when {4} secs elapsed... \n".format(threading.currentThread().name,start_scan_time, ip_address_to_scan, port_to_scan,configParams.max_scan_time,scan_num))
        onion_circuits = scan_torrouter(errors_fd,routers_list,ip_address_to_scan,port_to_scan,configParams.max_scan_time, ev)
        end_scan_time = time()
        print "{0}: The scan took {1} seconds".format(threading.currentThread().name,end_scan_time-start_scan_time)
        errors_fd.write("{0}: The scan took {1} seconds\n".format(threading.currentThread().name,end_scan_time-start_scan_time))
        log_time = int((end_scan_time + start_scan_time)/2)
        logs_fd.write("{0} : ".format(log_time))
        logs_fd.flush()
        circ_ids_list = onion_circuits.keys()
        for circ_id in circ_ids_list:
            fp = onion_circuits[circ_id].probed_router_fp
            ip = onion_circuits[circ_id].probed_router.ip_address.replace('.','-')
            port = onion_circuits[circ_id].probed_router.or_port
            state = onion_circuits[circ_id].state
            logs_fd.write("{0}.{1}({2}),".format(ip,port,state))
            logs_fd.flush()
        logs_fd.write("\n")
        logs_fd.flush()
        errors_fd.flush()
        
    except IOError as io_err:#(err_number, str_error):
        errmsg += ": There was an IOERROR exception: {}".format(repr(io_err))
        print errmsg
        caught_exception = True
        errors_fd.write(errmsg + "\n")
        errors_fd.flush()
    except TorException as str_error:
        errmsg += ": There was a TorException: {0}".format(repr(str_error))
        print errmsg
        caught_exception = True
        errors_fd.write(errmsg + "\n")
        errors_fd.flush()
    except ValueError:
        errmsg +=  ": Could not convert data to an integer."
        print errmsg
        caught_exception = True
        errors_fd.write(errmsg + "\n")
        errors_fd.flush()
    except:    
        errmsg += ": Unexpected error!"
        print errmsg
        print repr(sys.exc_info())
        caught_exception = True
        errors_fd.write(errmsg)
        errors_fd.write(repr(sys.exc_info()))
        errors_fd.write("\n")
        tb = traceback.format_exc()
        print tb
        errors_fd.flush()

    logs_fd.close()
    errors_fd.close()
    exit()


def main():
    parseCommandLineParameters(sys.argv)
    M2Crypto.threading.init()
    print "Starting the experiments  - {0} secs between scans".format(configParams.delay_between_scans)
    tor_net_state = tordirinfo.getTorNetworkStateFromFile(configParams.netstate_filename)
    routers_list = tor_net_state.router_list
    tordirinfo.sortRouterListByBandwidth(routers_list)
    if configParams.scan_guards_only:
        routers_list = getGuardsFromRouterList(routers_list)
    TOR_NET_STATE_LAST_UPDATE =tor_net_state.fetch_time_epoch_gmt
    targets = list()
    if(configParams.scan_target_ip != None):
      target = tordirinfo.getRouterByIpAndPort(configParams.scan_target_ip,configParams.scan_target_port,routers_list)
      targets.append(target)
    else:
      targets=copy.copy(routers_list)
    
    threads = list()
    for r in configParams.routers_to_scan:
        tokens = r.split(":")
	if(len(tokens) != 2):
	   print "Wrong format for {} (should be IP:PORT). Skipping.".format(r)
	   continue
        ip_address_to_scan = r.split(":")[0]
        port_to_scan = int(r.split(":")[1])
        
        rtr = tordirinfo.getRouterByIpAndPort(ip_address_to_scan,port_to_scan,routers_list)
        if rtr:
            print "{0}: Creating scanner for {1}:{2}, bw = {3}".format(threading.currentThread().name,ip_address_to_scan,port_to_scan,rtr.bandwidth_from_consensus)
            thr = threading.Thread(target = ScanRouter,\
               args=(ip_address_to_scan,port_to_scan,targets),\
               name = "scanner.{0}.{1}".format(ip_address_to_scan.replace('.','-'),port_to_scan))
	    threads.append(thr)
	    thr.start()
        else:
            print "{0}: {1}:{2} was not in the network state.".format(threading.currentThread().name,ip_address_to_scan,port_to_scan)
        
    tmer = threading.Timer(configParams.max_scan_time, terminate_threads)
    tmer.daemon = True
    tmer.start() 
    signal.signal(signal.SIGINT, signal_handler)
    while(not(ev.isSet())):
        sleep(1)
	all_dead = True
        for thread in threads:
            if thread.is_alive():
	        all_dead = False
		break
	if(all_dead):
	    ev.set()
    tmer.cancel()
    print "Scan is finished!"
    
if __name__ == "__main__":
  ev = threading.Event()
  main()
    
