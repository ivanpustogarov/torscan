#! /usr/bin/python

# Copyright (c) 2014-2015 Ivan Pustogarov
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import re, string, sys, urllib, base64, pickle,urllib2,torcrypto
import StringIO
from random import randint
from operator import itemgetter, attrgetter
import sets
import time

CONNECTION_TIMEOUT = 5

DIRECTORY_ADDRESS = "194.109.206.212:80"

init_directories = ["194.109.206.212:80",
     "82.94.251.203:80",
     "216.224.124.114:9030",
     "212.112.245.170:80",
     "193.23.244.244:80",
     "208.83.223.34:443",
     "213.115.239.118:443",
               "128.31.0.39:9131",
               "86.59.21.38:80"]

directories = ("194.109.206.212:80",
     "82.94.251.203:80",
     "216.224.124.114:9030",
     "212.112.245.170:80",
     "193.23.244.244:80",
     "208.83.223.34:443",
     "213.115.239.118:443",
               "128.31.0.39:9131",
               "86.59.21.38:80")


#  Wgg - Weight for Guard-flagged nodes in the guard position
#  Wgm - Weight for non-flagged nodes in the guard Position
#  Wgd - Weight for Guard+Exit-flagged nodes in the guard Position
#
#  Wmg - Weight for Guard-flagged nodes in the middle Position
#  Wmm - Weight for non-flagged nodes in the middle Position
#  Wme - Weight for Exit-flagged nodes in the middle Position
#  Wmd - Weight for Guard+Exit flagged nodes in the middle Position
#
#  Weg - Weight for Guard flagged nodes in the exit Position
#  Wem - Weight for non-flagged nodes in the exit Position
#  Wee - Weight for Exit-flagged nodes in the exit Position
#  Wed - Weight for Guard+Exit-flagged nodes in the exit Position
#
#  Wgb - Weight for BEGIN_DIR-supporting Guard-flagged nodes
#  Wmb - Weight for BEGIN_DIR-supporting non-flagged nodes
#  Web - Weight for BEGIN_DIR-supporting Exit-flagged nodes
#  Wdb - Weight for BEGIN_DIR-supporting Guard+Exit-flagged nodes
#
#  Wbg - Weight for Guard+Exit-flagged nodes for BEGIN_DIR requests
#  Wbm - Weight for Guard+Exit-flagged nodes for BEGIN_DIR requests
#  Wbe - Weight for Guard+Exit-flagged nodes for BEGIN_DIR requests
#  Wbd - Weight for Guard+Exit-flagged nodes for BEGIN_DIR requests

class BWWeights:
    # bs_scale is stored for informatin only. All wights are already divided by the scale
    Wgg = None
    Wgm = None
    Wgd = None
    
    Wmg = None
    Wmm = None
    Wme = None
    Wmd = None
    
    Weg = None
    Wem = None
    Wee = None
    Wed = None

class GlobalBwInfo:
    bw_weights = BWWeights()
    bw_scale = 10000.0
    
    total_weightened_bw_middles = None
    total_weightened_bw_exits = None
    
    total_unweightened_bw_guards = None
    total_unweightened_bw_middles = None
    
    
    def __init__(self):
        self.total_unweightened_bw_exits = None
        self.total_weightened_bw_guards = None
        
    

class TorNetworkState:

    #if consensus test is provided, we read fresh-until time
    # as the time when the consensus was published
    def __init__(self,consensus_text = None):
        if consensus_text:
            buf = StringIO.StringIO(consensus_text)
	    line = buf.readline()
	    while line and not("fresh-until" in line):
	        line = buf.readline()
	    # "fresh-until 2012-08-24 12:00:00"
            if "fresh-until" in line:
	        space_index = line.index(' ')
	        fresh_until_str = line[space_index+1:-1]
		fresh_until_struct = time.strptime(fresh_until_str,"%Y-%m-%d %H:%M:%S")
		self.fresh_until_epoch_gmt = time.mktime(fresh_until_struct)-time.timezone 
		

    fetch_time_epoch_gmt= 0
    fresh_until_epoch_gmt = 0
    #global_bw_info = GlobalBwInfo()
    router_list = None
    
    bw_scale = 10000.0    
    total_unweightened_bw_exits = None
    total_weightened_bw_guards = None    
    total_weightened_bw_middles = None
    
    total_weightened_bw_exits = None    
    total_unweightened_bw_guards = None
    total_unweightened_bw_middles = None
    
    Wgg = None
    Wgm = None
    Wgd = None
    
    Wmg = None
    Wmm = None
    Wme = None
    Wmd = None
    
    Weg = None
    Wem = None
    Wee = None
    Wed = None
    
        
    

class Router:
    name = ""
    ip_address = ""
    or_port = ""
    dir_port = ""
    fingerprint = ""
    uptime = 0
    onion_key = ""
    onion_key_base64 = ""
    onion_key_base64_multiline = "" #We need it because this is the format which is accepted by tarcrawl
    signing_key = ""
    signing_key_base64 = ""
    signing_key_base64_multiline = "" #We need it because this is the format whiwch is accepted by tarcrawl
    cicr_id = 0
    bandwidth_from_consensus = -1
    bandwidth_from_descriptor = -1
    flags = list()
    onion_skin = None
    version = None
    exit_policy = None
    
    def isGuard(self):
        for flag in self.flags:
            if flag == "Guard":
                return True
        return False
            
class RouterFlags:
    HSDIR = "HSDir"
    FAST = "Fast"
    STABLE = "Stable"
    EXIT = "Exit"
    GUARD = "Guard"


# Get the consensus text
# If filename is provided, reads the file
def getCurrentConsensusText(filename=None):
    global directories  
    consensus_text = None
    if filename:
        print "Reading the Consensus from file ... "    
        fd = open(filename,"rt")
	consensus_text = fd.read()
	return consensus_text
    print "Downloading the Consensus ... "    
    for dir_address in directories:
        try:
            print "Trying " + dir_address
            consensus_text = getCurrentConsensusText_from_address(dir_address)
            print "Consensus is downloaded!"
            break
        except IOError:
            print "Error occured while retreiving info from " + dir_address
            continue
    return consensus_text
    
def getCurrentConsensusText_from_address(address):
    cons_fd = urllib2.urlopen("http://"+address+"/tor/status-vote/current/consensus", timeout=CONNECTION_TIMEOUT)
    consensus_text = cons_fd.read()
    return consensus_text
    
def getRoutersFromConsensus(consensus_text):    
    
    buf = StringIO.StringIO(consensus_text)
    
    # Each relay is represented by these lines
    #r Unnamed /NE8d5S5BNRsFtrwYcqXYCaMBek 9b3Zg9BplrCEFCxgGBWvYoG+AKY 2012-05-18 03:16:19 50.7.246.50 9001 0
    #s Exit Running Valid
    #v Tor 0.2.2.35
    #w Bandwidth=20
    #p accept 20-23,43,53,79-81
    
    #Looking for the line describing a router
    router_list = list()
    p = re.compile(r"r (?P<name>\w+) (?P<identity>[\w\+/]+) (?P<desc_digest>[\w\+/]+) (\d\d\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d) (?P<ipaddress>[\d\.]+) (?P<orport>\d+) (?P<dirport>\d+)")
    line = buf.readline()
    while line:
        #Looking for the line describing a router
        m = p.match(line)
        if m:
            new_router = Router()
            ide_base64 = m.group('identity')+"="
            ide_binary = base64.standard_b64decode(ide_base64)
            ide_hex = ide_binary.encode("hex").upper()
            new_router.fingerprint = ide_hex
            new_router.name = m.group('name')
            new_router.ip_address = m.group('ipaddress')
            new_router.or_port = int(m.group('orport'))
            new_router.dir_port = int(m.group('dirport'))
            # Now read 


            #This is: s Exit Fast Guard HSDir Named Running Stable V2Dir Valid
            line_flags = buf.readline().rstrip()
	    #This is to skip "a " lines
	    while line_flags[:2] != "s ":
                line_flags = buf.readline().rstrip()
            flags = line_flags.split(" ")
	    #print flags
            flags.remove("s")
            new_router.flags = flags
            # Now go the version line: v Tor 0.2.2.35
            line_version = buf.readline().rstrip()
	    # Version is not obligatory
	    if(line_version[:2] == "v "):
                version_line_elements = line_version.split(" ")
                new_router.version = version_line_elements[2].rstrip()
	    else:
                new_router.version = "unknown"
            # w Bandwidth=20 (in case there was no version, we should be at bandwidth line)
	    line_bw = line_version
	    if(line_bw[:2] != "w "):
                line_bw = buf.readline().rstrip()
            new_router.bandwidth_from_consensus = int((line_bw.split(" ")[1]).split('=')[1])
            # p accept 20-23,43,53,79-81
            line_exit_policy = buf.readline().rstrip()
            new_router.exit_policy = line_exit_policy
            router_list.append(new_router)
        line = buf.readline()
    
    return router_list
    
    


# This fucntion returns a Router object
# Note that we do not use port number here,
#  so the default port is 80. We never use SSL.
def getDescriptor(fingerprint, address):
    a = urllib2.urlopen("http://"+address+"/tor/server/fp/"+fingerprint, timeout=CONNECTION_TIMEOUT)
    line = "init"
    new_router = Router()
    new_router.fingerprint = fingerprint
    p_router = re.compile(r"router (?P<name>\w+) (?P<ipaddress>[\d\.]+) (?P<orport>\d+) (?P<socksport>\d+) (?P<dirport>\d+)")
    p_uptime = re.compile(r"uptime (?P<uptime>\d+)")
    #first line should be "router ... "
    line = a.readline()
    m_router = p_router.match(line)
    if m_router:
        new_router.name = m_router.group('name')
        new_router.ip_address = m_router.group('ipaddress')
        new_router.or_port = m_router.group('orport')
        new_router.dir_port = m_router.group('dirport')
    # Got something but not the descriptor. can be a message that a TLS connection is required
    else:
        a.close()
	raise IOError
    #Search for uptime line, assume that it is in the descriptor
    while line:
        line = a.readline()
        #print "getDescriptor():: In search of uptime. parsing line: "+line
        m_uptime = p_uptime.match(line)
        if m_uptime:
            #print "getDescriptor():: I found uptime entry!"
            new_router.uptime = m_uptime.group('uptime')
            break
    # Immidiately after uptime should go bandwidth in the form : "bandwidth 5242880 10485760 7168". Hence we need to take 
    # the second element
    line = a.readline()
    elements = line.split(' ')
    new_router.bandwidth_from_descriptor = int(elements[1])
    #Searching for onion-key
    while line:
        line = a.readline()
        if line == "onion-key\n":
            #print "getDescriptor():: Found onion-key, about to read!"
            line = a.readline() #this is: -----BEGIN RSA PUBLIC KEY-----\n
            new_router.onion_key_base64_multiline = '\n'+line
            line = a.readline() #this is the first line of RSA pub key
            while line != "-----END RSA PUBLIC KEY-----\n":
                #print "getDescriptor():: read a line of RSA key!"
                new_router.onion_key_base64 = new_router.onion_key_base64+line.rstrip() #Get rid of '\n' char
                new_router.onion_key_base64_multiline = new_router.onion_key_base64_multiline+line
                line = a.readline()
            new_router.onion_key_base64_multiline = new_router.onion_key_base64_multiline+line
            break
    #The next line should be signing-key followed by RSA public key
    line = a.readline()
    if line == "signing-key\n":
        line = a.readline() #this is: -----BEGIN RSA PUBLIC KEY-----\n
        new_router.signing_key_base64_multiline = '\n'+line
        line = a.readline() #this is the first line of RSA pub key
        while line != "-----END RSA PUBLIC KEY-----\n":
            new_router.signing_key_base64 = new_router.signing_key_base64+line.rstrip() #Get rid of '\n' char
            new_router.signing_key_base64_multiline = new_router.signing_key_base64_multiline+line
            line = a.readline()
        new_router.signing_key_base64_multiline = new_router.signing_key_base64_multiline+line
    #Finally, decode RSA keys
    new_router.onion_key = base64.standard_b64decode(new_router.onion_key_base64)
    new_router.signing_key = base64.standard_b64decode(new_router.signing_key_base64)
    return new_router

                

def getRouterListFromFile(filename):
    pkl_file = open(filename, 'rb')
    router_list = pickle.load(pkl_file)
    pkl_file.close()
    return router_list

def putRouterListToFile(router_list,filename):
    pkl_file = open(filename,'wb')
    pickle.dump(router_list,pkl_file)
    pkl_file.close()
    
    
def getTorNetworkStateFromFile(filename):
    pkl_file = open(filename, 'rb')
    tor_net_state = pickle.load(pkl_file)
    pkl_file.close()
    return tor_net_state

def putTorNetworkStateToFile(tor_net_state,filename):
    pkl_file = open(filename,'wb')
    pickle.dump(tor_net_state,pkl_file)
    pkl_file.close()



#This function assumes that there one-to-one map between fp and router
def getRouterDictFromRouterList(router_list):
    router_dict = dict()    
    for router in router_list:
        router_dict[router.fingerprint] = router
    return router_dict
    
# This function assumes that there one-to-one map between hostname and router
# which can be wrong of course, so the caller must check it
def getRouterDictFromRouterListUsingHostname(router_list):
    router_dict = dict()    
    for router in router_list:
        hostname = getHostnameForRouter(router)
	if router_dict.has_key(hostname):
            print "tordirinfo.getRouterDictFromRouterListUsingHostname:: hostname dublication: {}".format(hostname)
        router_dict[hostname] = router
    return router_dict


#Takes router_list and fill BW field. By default this field is None
def fillRouterListWithBWFromConsensus(router_list):
    global directories    
    print "Trying to fill the router list with bandwith information from consensus ... "    
    for dir_address in directories:
        try:
            print "Trying " + dir_address
            fillRouterListWithBWFromConsensus_from_address(router_list,dir_address)
            print "Router list is updated with BW information from consensus!"
            break
        except IOError:
            print "Error occured while retreiving info from " + dir_address
            continue

def fillRouterListWithBWFromConsensus_from_address(router_list_from_S3,address):
    a = urllib2.urlopen("http://"+address+"/tor/status-vote/current/consensus", timeout=CONNECTION_TIMEOUT)
    line = "init" #otherwise while loop will not start
    line1 = "init"
    i = 0
    #Looking for the line describing a router
    p_router = re.compile(r"r (?P<name>\w+) (?P<identity>[\w\+/]+) (?P<digest>[\w\+/]+) (\d\d\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d) (?P<ipaddress>[\d\.]+) (?P<orport>\d+) (?P<dirport>\d+)")
    p_bandwidth = re.compile(r"w Bandwidth=(?P<bandwidth>\d+)")
    U = list() #Holds fingerprint in form "EE1E3C9714CFDF6A0079191CD2CF6DA69D33793A"
    routers_from_consensus = list()
    while line:
        line = a.readline()
        i = i+1
        m = p_router.match(line)
        if m:
            router = Router()         
            ide = m.group('identity')+"="
            data = base64.standard_b64decode(ide)
            data1 = data.encode("hex").upper()
            router.fingerprint = data1
            router.ip_address = m.group('ipaddress')
            U.append(data1)
            #This is: s Exit Fast Guard HSDir Named Running Stable V2Dir Valid
            line1 = a.readline()
            #This is: v Tor 0.2.2.34
            line1 = a.readline()
            #This is: w Bandwidth=4090
            line1 = a.readline()
            #Now look for bandwidth line 
            m1 = p_bandwidth.match(line1)
            router.bandwidth_from_consensus = int(m1.group('bandwidth'))
            for r_s3 in router_list_from_S3:
                if r_s3.fingerprint == router.fingerprint:
                    r_s3.bandwidth_from_consensus = router.bandwidth_from_consensus
                    break
            routers_from_consensus.append(router)
    return routers_from_consensus
        


def fillRouterListWithFalgsFromConsensus(router_list,consensus_filename = None):
    global directories    
    print "Trying to fill the router list with flags information from consensus ... "    
    
    if consensus_filename != None:
        fillRouterListWithFlagsFromConsensus_from_address(router_list,consensus_filename,is_address_local = True)
    else:
        for dir_address in directories:
            try:
                print "Trying " + dir_address
                fillRouterListWithFlagsFromConsensus_from_address(router_list,dir_address,is_address_local = False)
                print "Router list is updated with Flags information from consensus!"
                break
            except IOError:
                print "Error occured while retreiving info from " + dir_address
                continue

        
# Version will also be contined in flags
def fillRouterListWithFlagsFromConsensus_from_address(router_list_from_S3,address,is_address_local = False):
    if is_address_local:
        cons_fd = open(address,'rt')
    else:
        cons_fd = urllib2.urlopen("http://"+address+"/tor/status-vote/current/consensus", timeout=CONNECTION_TIMEOUT)
    line = "init" #otherwise while loop will not start
    line1 = "init"
    i = 0
    #Looking for the line describing a router
    p_router = re.compile(r"r (?P<name>\w+) (?P<identity>[\w\+/]+) (?P<digest>[\w\+/]+) (\d\d\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d) (?P<ipaddress>[\d\.]+) (?P<orport>\d+) (?P<dirport>\d+)")
    routers_from_consensus = list()
    while line:
        line = cons_fd.readline()
        i = i+1
        m = p_router.match(line)
        if m:
            router = Router()         
            ide = m.group('identity')+"="
            data = base64.standard_b64decode(ide)
            data1 = data.encode("hex").upper()
            router.fingerprint = data1
            router.ip_address = m.group('ipaddress')        
            #This is: s Exit Fast Guard HSDir Named Running Stable V2Dir Valid
            line1 = cons_fd.readline()
            router.flags = line1.split(" ")
            router.flags.remove("s")
            router.flags[len(router.flags)-1] = router.flags[len(router.flags)-1].rstrip()
            # This is: v Tor 0.2.2.35
            line1 = cons_fd.readline()
            version_line_elements = line1.split(" ")
            version = version_line_elements[2].rstrip()
            
            for r_s3 in router_list_from_S3:
                if r_s3.fingerprint == router.fingerprint:
                    r_s3.flags = router.flags
                    r_s3.version = version
                    break
            routers_from_consensus.append(router)
    return routers_from_consensus
    

# Fills TorNetworkState object with bw info: weights, total guard, exit bw.
# Uses file <consensus_filename> if given. 
# Uses raw consensus_text if given.
# consensus_text has priority over consensus_filename
# Download consensus from authorities otherwise.
def fillTorNetworkStateWithBWInfoFromConsensus(tor_net_state,consensus_filename = None,consensus_text = None):
    global directories    
    print "Trying to fill the TorNetworkState with bw information(total bw, weights, etc.) from consensus ... "    
    if consensus_filename != None:
        fillTorNetworkStateWithBWInfoFromConsensus_from_address(tor_net_state,consensus_filename,is_address_local = True)
    elif consensus_text != None:
        cons_buf = StringIO.StringIO(consensus_text)
        fillTorNetworkStateWithBWInfoFromConsensus_from_address(tor_net_state,cons_buf,is_address_local = False,is_address_buffer = True)
    else:
        for dir_address in directories:
            try:
                print "Trying " + dir_address
                fillTorNetworkStateWithBWInfoFromConsensus_from_address(tor_net_state,dir_address,is_address_local = False)
                print "TorNetworkState is updated with with bw information from consensus!"
                break
            except IOError:
                print "Error occured while retreiving info from " + dir_address
                continue
    
# address_pointer can be: remote IP:PORT, local filname, StringIO --> file_desc or stringbuffer by buf = StringIO.StringIO(consensus)
# an object which supports realine()
def fillTorNetworkStateWithBWInfoFromConsensus_from_address(tor_net_state,address_pointer,is_address_local = False,is_address_buffer = False):
    if is_address_buffer:
        cons_fd = address_pointer
    elif is_address_local:
        cons_fd = open(address_pointer,'rt')
    else:
        cons_fd = urllib2.urlopen("http://"+address_pointer+"/tor/status-vote/current/consensus", timeout=CONNECTION_TIMEOUT)
    line = cons_fd.readline()
    while line:
        if line.find("bandwidth-weights") >= 0:
            line = line.rstrip()
            break
        line = cons_fd.readline()

    weights_str_list = line.split(' ')
    for weight_str in weights_str_list[1:]: # First is "bandwidth-weights", so start from second
        weight_name = weight_str.split('=')[0]
        weight_value = int(weight_str.split('=')[1])/tor_net_state.bw_scale
        bw_weights_fill_weight(tor_net_state,weight_name, weight_value)
    tor_network_state_calculate_weightened_aggregated_bw(tor_net_state)
    tor_network_state_calculate_unweightened_aggregated_bw(tor_net_state)
        
        
        

#bandwidth-weights Wbd=1437 Wbe=0 Wbg=3211 Wbm=10000 
#                  Wdb=10000 
#                  Web=10000 Wed=7126 Wee=10000 Weg=7126 Wem=10000 
#                  Wgb=10000 Wgd=1437 Wgg=6789 Wgm=6789 
#                  Wmb=10000 Wmd=1437 Wme=0 Wmg=3211 Wmm=10000        
def bw_weights_fill_weight(tor_net_state, weight_name, weight_value):
    
    if weight_name == "Wbd":
        tor_net_state.Wbd = weight_value
    elif weight_name == "Wbe":
        tor_net_state.Wbe = weight_value
    elif weight_name == "Wbg":
        tor_net_state.Wbg = weight_value
    elif weight_name == "Wbm":
        tor_net_state.Wbm = weight_value
        
        
    elif weight_name == "Wdb":
        tor_net_state.Wdb = weight_value
        
        
    elif weight_name == "Web":
        tor_net_state.Web = weight_value
    elif weight_name == "Wed":
        tor_net_state.Wed = weight_value
    elif weight_name == "Wee":
        tor_net_state.Wee = weight_value
    elif weight_name == "Weg":
        tor_net_state.Weg = weight_value
    elif weight_name == "Wem":
        tor_net_state.Wem = weight_value
    
    elif weight_name == "Wgb":
        tor_net_state.Wgb = weight_value
    elif weight_name == "Wgd":
        tor_net_state.Wgd = weight_value
    elif weight_name == "Wgg":
        tor_net_state.Wgg = weight_value
    elif weight_name == "Wgm":
        tor_net_state.Wgm = weight_value
        
        
    elif weight_name == "Wmb":
        tor_net_state.Wmb = weight_value
    elif weight_name == "Wmd":
        tor_net_state.Wmd = weight_value
    elif weight_name == "Wme":
        tor_net_state.Wme = weight_value
    elif weight_name == "Wmg":
        tor_net_state.Wmg = weight_value        
    elif weight_name == "Wmm":
        tor_net_state.Wmm = weight_value
    else:
        print "Unknown weight! Aborting!"
        exit()
    
        
def tor_network_state_calculate_weightened_aggregated_bw(tor_net_state):
    bw_weights = tor_net_state#tor_net_state.global_bw_info.bw_weights
    if tor_net_state.router_list == None:
        print "Trying calculate tor network aggregated bandwidths using an empty router_list. Aborting!"
        exit()
    total_weightened_bw_guards = 0
    total_weightened_bw_exits = 0
    total_weightened_bw_middles = 0    
    for r in tor_net_state.router_list:
        
        # BW for guards        
        if ("Guard" in r.flags):
            if ("Exit"  in r.flags):
                weight = bw_weights.Wgd
            else:
                weight = bw_weights.Wgg
            total_weightened_bw_guards += r.bandwidth_from_consensus*weight
        
        # BW for exits
        if ("Exit" in r.flags):
            if ("Guard" in r.flags):
                weight = bw_weights.Wed
            else:
                weight = bw_weights.Wee
            total_weightened_bw_exits += r.bandwidth_from_consensus*weight
            
        # BW for middles = for all
        if ("Exit" in r.flags) and ("Guard" in r.flags):
            weight = bw_weights.Wmd
        elif ("Guard" in r.flags):
            weight = bw_weights.Wmg
        elif ("Exit" in r.flags):
            weight = bw_weights.Wme
        else:
            weight = bw_weights.Wmm
        total_weightened_bw_middles += r.bandwidth_from_consensus*weight
    
    tor_net_state.total_weightened_bw_guards = total_weightened_bw_guards
    tor_net_state.total_weightened_bw_exits = total_weightened_bw_exits
    tor_net_state.total_weightened_bw_middles = total_weightened_bw_middles
    
    return
    
def tor_network_state_calculate_unweightened_aggregated_bw(tor_net_state):
    total_unweightened_bw_guards = 0
    total_unweightened_bw_middles = 0
    total_unweightened_bw_exits = 0
    for r in tor_net_state.router_list:
        if ("Guard" in r.flags):
            total_unweightened_bw_guards += r.bandwidth_from_consensus
        if ("Exit" in r.flags):
            total_unweightened_bw_exits += r.bandwidth_from_consensus
        
        total_unweightened_bw_middles += r.bandwidth_from_consensus
    
    tor_net_state.total_unweightened_bw_guards = total_unweightened_bw_guards    
    tor_net_state.total_unweightened_bw_exits = total_unweightened_bw_exits
    tor_net_state.total_unweightened_bw_middles = total_unweightened_bw_middles
    
        
        
    

    
def sortRouterListByBandwidth(router_list):
    router_list.sort(key=attrgetter('bandwidth_from_consensus'), reverse=True)
    return
    
    
def getRouterByIpAndPort(ip,port,router_list_from_S3):
    for r in router_list_from_S3:
        if r.ip_address == ip and int(r.or_port) == int(port):
            return r
    return None

# Returns the firs router with the name provided
# or None if no router was found
def getRouterByName(name,router_list_from_S3):
    for r in router_list_from_S3:
        if r.name == name:
            return r
    return None
    
def getRouterByFingerprint(fp,router_list_from_S3):
    for r in router_list_from_S3:
        if r.fingerprint == fp:
            return r
    return None

# Tries to find the router for x_name
def getRouterByX(x_name,router_list_from_S3):
    # first let's try to find the target router by name
    target_router = getRouterByName(x_name,router_list_from_S3)
    # if no luck, maybe the hostname was provided
    if target_router == None:
        try:
            target_router = getRouterByHostname(x_name,router_list_from_S3)
	except:
	    target_router = None
    # if no luck, maybe the fingerprint was provided
    if target_router == None:
        try:
            target_router = getRouterByFingerprint(x_name,router_list_from_S3)
	except:
	    target_router = None
    return target_router

def fillRouterListWithOnionSkins(router_list):
    print "Creating onion skins for routers ... "    
    for router in router_list:
	if router.onion_key_base64_multiline == "":
		print "Warning! Request to create an onion skin for a relay without onion key! Skipping!"
		continue
        (onionskin, x) = torcrypto.create_onion_skin(router.onion_key_base64_multiline)
        router.onion_skin = onionskin
    print "Created"
    
def getHostnameByIpAndPort(ip,port):
    ip_with_dashes = ip.replace('.','-')
    hostname = ip_with_dashes + "." + str(port)
    return hostname
    
def getHostnameForRouter(r):
    hostname = getHostnameByIpAndPort(r.ip_address,r.or_port)
    return hostname

# hostname = 83-227-52-173.9001
def getRouterByHostname(hostname,router_list):
    dot_index = hostname.find('.')
    port = int(hostname[dot_index+1:])
    
    ip_dashed = hostname[:dot_index]
    ip = ip_dashed.replace('-','.')
    
    r = getRouterByIpAndPort(ip,port,router_list)
    return r
    
#Note that the fist bin is 1. Fro example. if you choose a bin size of 50 and you have a bw of say 23, it will go to the first bin and not to zeroth bin
def makeBWHistogram(router_list,bw_bin_size):
    histogram = dict()
    for r in router_list:
        bw = int(r.bandwidth_from_consensus)
        bin_num = bw/int(bw_bin_size)
        if histogram.has_key(bin_num):
            histogram[bin_num] += 1
        else:
            histogram[bin_num] = 1
            
    for bin_num in histogram:
        histogram[bin_num] = float(histogram[bin_num])/float(len(router_list))
    
    
    return histogram


    
def sortRoutersByBWConsBWDescRatio(router_list):
    router_list = sorted(router_list,key=lambda r:r.bandwidth_from_consensus/r.bandwidth_from_descriptor,reverse=False)
    return None
   

def filterRouterListByFlag(router_list,flags_list_filter):
    filtered_list = list()
    flags_set_filter = sets.Set(flags_list_filter)
    for r in router_list:
        r_flags_set = sets.Set(r.flags)
	#test whether every element in flags_set_filter is in r_flags_set
	if r_flags_set.issuperset(flags_set_filter):
	    filtered_list.append(r)
    return filtered_list


