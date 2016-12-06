#! /usr/bin/python

# Copyright (c) 2014-2015 Ivan Pustogarov
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import sys
from torlib import tordirinfo
import random, threading
from time import time
import signal

VERSION = 1.00
NUMBER_OF_DOWNLOADED_DESCRIPTORS = 0
NUMBER_OF_DOWNLOADED_DESCRIPTORS_lock = threading.Lock()

class ConfigParams:

    consensus_filename = None 
    tor_net_state_filename = None
    build_onion_skins = True
    download_descriptors = True

    def init_from_command_line(self,arg_list):
        if ("--consensus" in arg_list): # input consensus filename 
            self.consensus_filename = arg_list.pop(arg_list.index('--consensus')+1)
            arg_list.remove("--consensus")

        if ("-o" in arg_list): # output filename with tor_net_state 
            self.tor_net_state_filename = arg_list.pop(arg_list.index('-o')+1)
            arg_list.remove("-o")

        if ("--no-skins" in arg_list): # if present, no onion skins will be built 
            self.build_onion_skins = False
            arg_list.remove("--no-skins")

        if ("--no-descriptors" in arg_list): # if set, no descriptors will be downloaded and no skins will be built 
            self.build_onion_skins = False
            self.download_descriptors = False
            arg_list.remove("--no-descriptors")

        if ("-h" in arg_list): # show help and exit 
    	    print_usage_and_exit()
    
        if len(arg_list) > 1:
            print "Unknown params: {}".format(arg_list[1:])
    	    print_usage_and_exit()

def signal_handler(signal, frame):
    print "Received CTRL-C. Exiting, no clean-up done"
    sys.exit(0)
        

def print_usage_and_exit():
    print """Usage: getconsensus      
                                      [-o output-file] 
                                      [--consensus consensus-filename] 
				      [--no-skins]
				      [--no-desciptors]

	     Download consensus document and router descriptors from one
	     of the tor authorities, compute onion skins and save
	     routers info in  a a file ('netstate' by default) that can
	     be used by torscan.
				      """
    exit()

def load_fingerprints():
    print "Loading consensus ... "
    dir_num = 0
    fingerprints = None
    for dir_address in tordirinfo.directories:
        try:
            print "Trying " + dir_address
            fingerprints = tordirinfo.getFingerprintsFromConsensus(dir_address)
            print "Consensus loaded!"
            break
        except IOError:
            dir_num = dir_num+1
            print "Error occured while retreiving info from " + dir_address
            continue
    return fingerprints
    
def check_fps_for_repetitions(fingerprints):
    print "Checking fingerprints for repetitions ... "
    for i in range(len(fingerprints)):
        for j in range(i+1,len(fingerprints)):
            if fingerprints[i] == fingerprints[j]:
                print "We found a repetition in consensus!"
    print "Checked!\n"


def update_router_from_desc(router,router_list):
    global NUMBER_OF_DOWNLOADED_DESCRIPTORS
    global NUMBER_OF_DOWNLOADED_DESCRIPTORS_lock
    #new_router = None
    addresses = list(tordirinfo.directories)
    random.shuffle(addresses)
    desc = None
    for dir_address in addresses:
        try:
            desc = tordirinfo.getDescriptor(router.fingerprint, dir_address)
            break
        except IOError:
            continue
    if desc:
        router.uptime = desc.uptime
        router.onion_key = desc.onion_key
        router.onion_key_base64 = desc.onion_key_base64
        router.onion_key_base64_multiline = desc.onion_key_base64_multiline
        router.signing_key = desc.signing_key
        router.signing_key_base64 = desc.signing_key_base64
        router.signing_key_base64_multiline = desc.signing_key_base64_multiline
        router.bandwidth_from_descriptor = desc.bandwidth_from_descriptor
        #print router.bandwidth_from_descriptor
        NUMBER_OF_DOWNLOADED_DESCRIPTORS_lock.acquire()
        NUMBER_OF_DOWNLOADED_DESCRIPTORS += 1    
        if NUMBER_OF_DOWNLOADED_DESCRIPTORS % 500 == 0:
            print "We have %d descriptors so far" % NUMBER_OF_DOWNLOADED_DESCRIPTORS
        NUMBER_OF_DOWNLOADED_DESCRIPTORS_lock.release()
    else:
        print "Was not able to download desc for {}. No key material will be available: take care when creating onion skins.".format(router.fingerprint)
        
    
def wait_nonmain_threads_dead():
    time1 = time()
    time2 = time()
    while True:
        threads = threading.enumerate()
        num_of_alive = 0
        for thread in threads:
            if thread.is_alive():
                num_of_alive += 1  
        if num_of_alive == 1: # Only main thread is left
            break
        time2 = time()
        if time2-time1 > 10:
            time1 = time()
            print "We're waiting for {0} fingerprints!".format(num_of_alive-1)

def get_num_of_alive_threads():
    threads = threading.enumerate()
    num_of_alive = 0
    for thread in threads:
        if thread.is_alive():
            num_of_alive += 1  
    return num_of_alive

# For each router in <router_list> downloads the correseponding
# descriptor from one of the authorities.
def load_descriptors_from_authorities(routers_list):    
    print "Loading descriptors from default authorities (it might take a while)... "
    #router_list_lock = threading.Lock()
    i=0
    threads = list()
    for r in routers_list:    
        thr = threading.Thread(target = update_router_from_desc,\
                args=(r,routers_list),\
                name = "fetcher-{0}".format(i))
	threads.append(thr)
	thr.daemon=True
	thr.start()
    
        while (get_num_of_alive_threads()>300):
            pass
        i += 1
    
    wait_nonmain_threads_dead()
    print "%d Descriptors loaded!" % NUMBER_OF_DOWNLOADED_DESCRIPTORS
    
def main():
    print "getconsensus, version {0}".format(VERSION)
    config_params = ConfigParams()

    config_params.init_from_command_line(sys.argv)
    if config_params.tor_net_state_filename == None:
      config_params.tor_net_state_filename = "netstate"

    consensus_txt = tordirinfo.getCurrentConsensusText(config_params.consensus_filename)
    routers_list = tordirinfo.getRoutersFromConsensus(consensus_txt)
    print "We have %d fingerprints" % len(routers_list)
    
    signal.signal(signal.SIGINT, signal_handler)
    if config_params.download_descriptors == True:
        load_descriptors_from_authorities(routers_list)
    else:
        print "No descriptors will be downloaded."
    
    if config_params.build_onion_skins == True:
        tordirinfo.fillRouterListWithOnionSkins(routers_list)
    else:
        print "Will not compute onion skins."
    
    tor_network_state = tordirinfo.TorNetworkState(consensus_txt)
    print "Created tor_networks_state object with fresh-until = {}".format(tor_network_state.fresh_until_epoch_gmt)
    tor_network_state.fetch_time_epoch_gmt = time()
    tor_network_state.router_list = routers_list
    tordirinfo.fillTorNetworkStateWithBWInfoFromConsensus(tor_network_state,consensus_filename = None,consensus_text = consensus_txt)
    
    print "Saving tor-net-state to \"{}\"".format(config_params.tor_net_state_filename)
    tordirinfo.putTorNetworkStateToFile(tor_network_state,config_params.tor_net_state_filename)
    print "File is created! See \"{0}\"".format(config_params.tor_net_state_filename)

if __name__ == "__main__":
    ev = threading.Event()
    main()


