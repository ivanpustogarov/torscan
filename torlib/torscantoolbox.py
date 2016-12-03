#! /usr/bin/python

# Copyright (c) 2014-2015 Ivan Pustogarov
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


import sys
sys.path.append("../")
from torcrawl import * 
from random import randint
import tordirinfo
from time import time,sleep,strftime,gmtime
from torcrypto import InvalidPKCS1Exception
import ctypes
import errno
import select
import math
import datetime
import threading
import M2Crypto

VERSION = 0.01

TOR_CLIENT_IDENTITY_CERT_FILENAME = 'tor_ca.pem' #ca in the filename stands for cert. authority
TOR_CLIENT_IDENTITY_PRIVATEKEY_FILENAME = 'tor_ca.key'

TOR_CLIENT_ONION_CERT_FILENAME = 'tor_client.pem'
TOR_CLIENT_ONION_PRIVATEKEY_FILENAME = 'tor_client.key'

FILENAME_LENGTH = 0
SECONDS_TO_CHECK_LIVE_THREADS = 30

class OR_Circuit:
    
    (CREATE_PENDING,                             #0
    CREATE_SENT,                                 #1
    CREATED_RECEIVED,                            #2
    EXTEND_SENT,                                 #3
    
    RELAY_EXTENDED_RECEIVED,                     #4
    RELAY_TRUNCATED_PROTOCOL_RECEIVED,           #5
    RELAY_TRUNCATED_HIBERNATING_RECEIVED,        #6
    RELAY_TRUNCATED_RESOURCELIMIT_RECEIVED,      #7
    RELAY_TRUNCATED_CONN_FAILED_RECEIVED,        #8
    RELAY_TRUNCATED_OR_CONN_CLOSED_RECEIVED,     #9
    RELAY_TRUNCATED_DESTROYED_RECEIVED,          #10
    RELAY_TRUNCATED_OTHER_RECEIVED,              #11
    RELAY_OTHER_RECEIVED,                        #12
    
    DESTROY_TOR_PROTOCOL_RECEIVED,               #13
    DESTROY_CONN_FAILED_RECEIVED,                #14
    DESTROY_OR_CONN_CLOSED_RECEIVED,             #15
    DESTROY_OTHER_RECEIVED) = range(0,17)        #16
    
    
    def __init__(self, circ_id, X, Y, state, ip,fingerprint,router = None):
        self.circ_id = circ_id
        self.X = X
        self.Y = Y
        self.state = state
        self.probed_router_ip = ip
        self.probed_router_fp = fingerprint
        self.probed_router = None        
        self.Kf = None
        self.Kb = None
        self.Df = None
        self.Db = None
        self.f_aes_counter = None
        self.b_aes_counter = None
        if router != None:
            self.probed_router = router
        
    def setKeys(self,Kf,Kb,Df,Db,f_aes_counter, b_aes_counter):
        self.Kf = Kf
        self.Kb = Kb
        self.Df = Df
        self.Db = Db
        self.f_aes_counter = f_aes_counter
        self.b_aes_counter = b_aes_counter

    

# Takes a router list (fetched from S3)
# Returns the subset initial list with routers which have guard flag
def getGuardsFromRouterList(routers_list):
    guards_list = list()    
    for router in routers_list:
        for flag in router.flags:
            if flag == "Guard":
                guards_list.append(router)
                break
    return guards_list



# Creates a random two certificates chain, and certs and keys to files.
#
# Returns a tuple (TOR_CLIENT_IDENTITY_CERT_FILENAME,
#                  TOR_CLIENT_IDENTITY_PRIVATEKEY_FILENAME,
#                  TOR_CLIENT_ONION_CERT_FILENAME,
#                  TOR_CLIENT_ONION_PRIVATEKEY_FILENAME)
#
# All the certificates and keys are saved to files. Filenames are generated randomly:
# filename = seed.RANDOM_STRING.[identity | onion].[pem | key]
# Since we're going to make many certificates, we MUST avoid
# filename collisions. That is why we should provide a new value of seed each time.
# Router's fingerprint that we're going to scan seems to be a good option for the seed.
def create_and_save_certs_for_client(seed = ''):
    tor_ca_cert = TorCertificate(1024)
    tor_client_cert = TorCertificate(1024, False, tor_ca_cert.cert.get_issuer(), tor_ca_cert.keypair)

    tor_client_identity_cert_filename = TorCertificate.random_file_name(FILENAME_LENGTH,seed,'.identity.pem')
    tor_client_identity_privatekey_filename = TorCertificate.random_file_name(FILENAME_LENGTH,seed,'.identity.key')
    
    tor_client_onion_cert_filename = TorCertificate.random_file_name(FILENAME_LENGTH,seed,'.onion.pem')    
    tor_client_onion_privatekey_filename = TorCertificate.random_file_name(FILENAME_LENGTH,seed,'.onion.key')
    
    tor_ca_cert.cert.save_pem(tor_client_identity_cert_filename)
    tor_ca_cert.keypair.save_key(tor_client_identity_privatekey_filename, cipher=None)
    tor_client_cert.cert.save_pem(tor_client_onion_cert_filename)
    tor_client_cert.keypair.save_key(tor_client_onion_privatekey_filename, cipher=None)
    
    return (tor_client_identity_cert_filename,tor_client_identity_privatekey_filename,tor_client_onion_cert_filename,tor_client_onion_privatekey_filename)
    
# Given a list <filenames> of filesnames, removes files under these names
# in the current directiry
# We need in order to delete files created by "create_and_save_certs_for_client" function
def remove_files(filenames):
    for filename in filenames:
        os.remove(filename)

    
def fill_with_create_cells(router_list, pending_cells, circuits, cicr_id_start):
    global CREATE_CELLS_PENDING    
    circID = cicr_id_start
    for router in router_list:
	if router.onion_skin == None:
		print "Warning! Tried to make cells for a relay {0} without onion skin! Skipping!".format(router.fingerprint)
		continue
        router.circ_id = circID        
        circID = circID + 1
        #X = os.urandom(HASH_LEN)
        X = CLIENT_DH_EXPONENT
        circuits[circID] = OR_Circuit(circID,X,None,OR_Circuit.CREATE_PENDING,\
                                        router.ip_address,router.fingerprint,router)
        pending_cells.append(TorCell(circID, TorCell.CREATE_FAST, X))

    
        
def send_cells(or_connection,pending_cells, or_circuits):

    or_connection.socket.setblocking(1)
    #written_cells = 0
    #print "Going to blocking write."
    #print "len(pending_cells) = %d" % len(pending_cells)
    cells_to_send = 50 
    pending_cells_len = len(pending_cells)
    if pending_cells_len < cells_to_send:
        cells_to_send = pending_cells_len
    # Send last 50 cells
    write_success = True
    try:
        written_bytes = or_connection.write_cells(pending_cells[pending_cells_len-cells_to_send:pending_cells_len])
    except M2Crypto.SSL.SSLError as ssl_error:
        print "{}: Caught SSL exception({}) when trying to write cells. State = {}!".format(threading.currentThread().name,repr(ssl_error), repr(or_connection.socket.get_state()))
	write_success = False
    #print "Returned from blocking write, written_bytes = %d" % written_bytes
    #print "Error code = {0}".format(ctypes.get_errno())
    or_connection.socket.setblocking(0)    
    #if write_success == False:
    #    return
    for i in range(pending_cells_len-cells_to_send,pending_cells_len):
        cell = pending_cells.pop()
        if cell.command == 5: #if create_fast_cell
            or_circuits[cell.circuit_id].state = OR_Circuit.CREATE_SENT
        elif cell.command == 9: #if extend_cell # RELAY_EARLY
            or_circuits[cell.circuit_id].state = OR_Circuit.EXTEND_SENT
                
    #print "len(pending_cells) = %d" % len(pending_cells)
    #print "Written %d cells in a row" % written_cells
     
#debugExtendAppended = 0
def processCreatedCell(orconn,circuits,pending_cells,reply_cell):

    router = circuits[reply_cell.circuit_id].probed_router

    #extend_cell = RelayCell.EXTEND_CELL(router.signing_key_base64_multiline, router.onion_key_base64_multiline, '127.0.0.1', 1)
    EXTEND_IP = router.ip_address
    EXTEND_PORT = 1
    extend_cell = RelayCell.EXTEND_CELL(router.signing_key_base64_multiline, router.onion_skin, EXTEND_IP, EXTEND_PORT,router.fingerprint.decode('hex'))
    curr_circ = circuits[reply_cell.circuit_id]
    orconn.update_keys(curr_circ.X, reply_cell)
    encrypted_cell = TorCell(reply_cell.circuit_id, TorCell.RELAY_EARLY, orconn.encrypt_cell(extend_cell).pack())
    curr_circ.setKeys(orconn.Kf,orconn.Kb,orconn.Df,orconn.Db,orconn.f_aes_counter, orconn.b_aes_counter)
    pending_cells.append(encrypted_cell)
    curr_circ.state = OR_Circuit.CREATED_RECEIVED
    #global debugExtendAppended
    #debugExtendAppended += 1
    #print "debugExtendAppnded = %d" % debugExtendAppended
    

    
    
def processRelayCell(errors_fd,orconn,circuits,reply_cell):

    if not (circuits[reply_cell.circuit_id].state in range(OR_Circuit.RELAY_EXTENDED_RECEIVED,OR_Circuit.DESTROY_OTHER_RECEIVED+1)):
      
        curr_circ = circuits[reply_cell.circuit_id]
        orconn.switch_keys(curr_circ.Kf,curr_circ.Kb,curr_circ.Df,curr_circ.Db,curr_circ.f_aes_counter,curr_circ.b_aes_counter)
        #print "Decrypting ... "
        inner_relay_cell = RelayCell(0,0,[])
        inner_relay_cell.unpack(reply_cell.payload)
        decrypted_inner_relay_cell = orconn.decrypt_cell(inner_relay_cell)
        if decrypted_inner_relay_cell != None:
        
            if decrypted_inner_relay_cell.relay_cmd == 7: # EXTENDED
                circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_EXTENDED_RECEIVED

            elif decrypted_inner_relay_cell.relay_cmd == 9: # TRUNCATED
                #circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_RECEIVED ########
                data = decrypted_inner_relay_cell.data
                truncated_err_code = "{0}{1}".format(binascii.hexlify(data)[0],binascii.hexlify(data)[1])
                #truncated_err_code = data[0]
                if truncated_err_code == "01":
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_PROTOCOL_RECEIVED
                elif truncated_err_code == "04":
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_HIBERNATING_RECEIVED
                elif truncated_err_code == "05":
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_RESOURCELIMIT_RECEIVED
                elif truncated_err_code == "06":
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_CONN_FAILED_RECEIVED
                elif truncated_err_code == "08":
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_OR_CONN_CLOSED_RECEIVED
                elif truncated_err_code == "11":
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_DESTROYED_RECEIVED
                else:
                    circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_TRUNCATED_OTHER_RECEIVED
                #print "Recived a RELAY_TRUNCATED cell with error code %s" % truncated_err_code

            elif decrypted_inner_relay_cell.relay_cmd == 10: # DROP
                circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_OTHER_RECEIVED
                print "Received RELAY_DROP cell. Ignoring"
                errors_fd.write("Received RELAY_DROP cell. Ignoring\n")
            else:
                circuits[reply_cell.circuit_id].state = OR_Circuit.RELAY_OTHER_RECEIVED
                print "Received RELAY cell with code {0}. Ignoring".format(decrypted_inner_relay_cell.relay_cmd)
                errors_fd.write("Received RELAY cell with code {0}. Ignoring\n".format(decrypted_inner_relay_cell.relay_cmd))
                
        else:
            #print "Could not decrypt the cell: either unrecognized or digest does not match! Consider {0} as non-scanned".format(circuits[reply_cell.circuit_id].probed_router_fp)
            #print "cmd = {0}".format(inner_relay_cell.relay_cmd)
#            errors_fd.write("{0} : Could not decrypt the cell: either unrecognized or digest does not match! Consider {1}\
#            as non-scanned; cmd ] {2}\n".format(time(),circuits[reply_cell.circuit_id].probed_router_fp,inner_relay_cell.relay_cmd))
            pass
    else:
#        print "Got a RELAY cell after a RELAY cell or a DESTROY CELL"                        
#        errors_fd.write("{0} : Got a RELAY cell after a RELAY or a DESTROY cell. Ignoring \
#        for router with fp = {1}, name = {2} on circ_id = {3} err_code = {4}\n!".format(time(),\
#        circuits[reply_cell.circuit_id].probed_router.fingerprint,\
#        circuits[reply_cell.circuit_id].probed_router.name,\
#        reply_cell.circuit_id,err_code))
        pass
        #errors_fd.flush()
    
    
def processDestroyCell(errors_fd,circuits,reply_cell):

    payload = reply_cell.payload
    err_code = "{0}{1}".format(binascii.hexlify(payload)[0],binascii.hexlify(payload)[1])
    
    if not (circuits[reply_cell.circuit_id].state in range(OR_Circuit.RELAY_EXTENDED_RECEIVED,OR_Circuit.DESTROY_OTHER_RECEIVED+1)):
        
        if err_code == "06": #This is CONNECT FAILED Error code
            circuits[reply_cell.circuit_id].state = OR_Circuit.DESTROY_CONN_FAILED_RECEIVED
#            errors_fd.write("{0} : We got DESTROY CONN FAILED error message in\
#            a destroy cell for router with fp = {1}, name = {2} on circ_id = {3}\n".format(time(),\
#            circuits[reply_cell.circuit_id].probed_router.fingerprint,\
#            circuits[reply_cell.circuit_id].probed_router.name,\
#            reply_cell.circuit_id))
            #errors_fd.flush()
        elif err_code == "08": # This is OR CONN CLOSED error code
            circuits[reply_cell.circuit_id].state = OR_Circuit.DESTROY_OR_CONN_CLOSED_RECEIVED
        elif err_code == "01": # This is Tor Procotcol Error code, consider the router as non-scanned one
            circuits[reply_cell.circuit_id].state = OR_Circuit.DESTROY_TOR_PROTOCOL_RECEIVED
            #connected_routers_list.append(circuits[reply_cell.circuit_id].probed_router)
#            errors_fd.write("{0} : We got TOR PROTOCOL error message in\
#            a destroy cell for router with fp = {1}, name = {2} on circ_id = {3}\n".format(time(),\
#            circuits[reply_cell.circuit_id].probed_router.fingerprint,\
#            circuits[reply_cell.circuit_id].probed_router.name,\
#            reply_cell.circuit_id))
            #errors_fd.flush()
        else:
            #circuits[reply_cell.circuit_id].state = OR_Circuit.EXTENDED_RECEIVED
            #DESTROY_OTHER_CELLS_RECEIVED += 1
            circuits[reply_cell.circuit_id].state = OR_Circuit.DESTROY_OTHER_RECEIVED
            #connected_routers_list.append(circuits[reply_cell.circuit_id].probed_router)
#            errors_fd.write("{0} : We got DESTROY cell with error message {1} in\
#            for router with fp = {2}, name = {3} on circ_id = {4}\n".format(time(),err_code,\
#            circuits[reply_cell.circuit_id].probed_router.fingerprint,\
#            circuits[reply_cell.circuit_id].probed_router.name,\
#            reply_cell.circuit_id))
            #errors_fd.flush()
    else:
#        print "Got a DESTROY cell after RELAY or DESTROY cell"
        pass
#        errors_fd.write("{0} : Got a DESTROY cell after RELAY after RELAY or DESTROY cell. Ignoring \
#        for router with fp = {1}, name = {2} on circ_id = {3} err_code = {4}\n!".format(time(),\
#        circuits[reply_cell.circuit_id].probed_router.fingerprint,\
#        circuits[reply_cell.circuit_id].probed_router.name,\
#        reply_cell.circuit_id,err_code))
        #errors_fd.flush()
    
    
    


def receive_cells(errors_fd,orconn,pending_cells, circuits):
#    global errors_fd  
    
    reply_cell = orconn.read_cell()
    
    
    while reply_cell != None:
        if not(circuits.has_key(reply_cell.circuit_id)):
            print "Received cell from an unknown circuit number = {0}".format(reply_cell.circuit_id)
            #print "My curcuits numbers are: {0}".format(circuits.keys())
            print "Ignorint this cell"
            errors_fd.write("{0} :Received cell from an unknown circuit number = {1}.Ignoring this cell\n".format(time(),reply_cell.circuit_id))
            pass
        elif reply_cell.command == 0: # Padding
            print "Got a PADDING cell which I ignored."
            errors_fd.write("Got a PADDING cell which I ignored.\n")
            pass
        elif reply_cell.command == 6: # CREATED
            processCreatedCell(orconn,circuits,pending_cells,reply_cell)

    
        elif reply_cell.command == 3: # Relay
            processRelayCell(errors_fd,orconn,circuits,reply_cell)
           
        elif reply_cell.command == 4: # Destroy
            processDestroyCell(errors_fd,circuits,reply_cell)
                                    
        else:
            err_time = time()                    
            print "{0}: Wow, got a strange cell (code = {1})!".format(err_time, reply_cell.command)
            errors_fd.write("{0}: Wow, got a strange cell (code = {1})!\n".format(err_time, reply_cell.command))
            try:
                errmsg = "{0}: Got an unknown cell with code" + \
                         "{1} for router with fp = {2}," + \
                         "name = {3} on circ_id = {4}\n!". \
                         format(err_time,reply_cell.command,\
                                circuits[reply_cell.circuit_id].probed_router.fingerprint,\
                                circuits[reply_cell.circuit_id].probed_router.name,\
                                reply_cell.circuit_id)
            except KeyError:
                errmsg = "{0}: Got an unknown cell with code " + \
                         "{1} and circ id {2}".format(err_time,reply_cell.command, reply_cell.circuit_id)
            raise TorException(errmsg)
        reply_cell = orconn.read_cell()
    



def doScan(errors_fd,orconn,pending_cells,circuits,num_to_finish,maxScanTimeSecs):

    start_scan_time = current_time = time()
    num_finished = 0
    # Start sedning and receiving the cells    
    while (num_finished < num_to_finish) and ( (time()-start_scan_time)<maxScanTimeSecs ) :

        time_left = maxScanTimeSecs - (time() - start_scan_time)
        if time_left < 0:
             time_left = 0
        if len(pending_cells) > 0:
            (rlist,wlist,xlist) = select.select([orconn.socket],[orconn.socket],[],time_left)
        else:
            (rlist,wlist,xlist) = select.select([orconn.socket],[],[],time_left)


        if wlist != []:
	    #send_start_time = int(time())
            send_cells(orconn,pending_cells,circuits)        
	    #send_end_time = int(time())
            #errors_fd.write("{}: I was sending 50 cells for {} seconds\n".format(threading.currentThread().name,send_end_time - send_start_time))
        if rlist != []:
	    #receive_start_time = int(time())
            receive_cells(errors_fd,orconn,pending_cells,circuits)
	    #receive_end_time = int(time())
            #errors_fd.write("{}: I was receiving cells for {} seconds\n".format(threading.currentThread().name,receive_end_time - receive_start_time))

        
#        time_delta = time()-current_time
        num_finished = getNumberOfFinished(circuits)
#        if time_delta > 3:
#            current_time = time()
#            print "{0}: {1} >> Finished {2} circuits".format(threading.currentThread().name,math.ceil(time()-start_scan_time),num_finished)
    num_finished = getNumberOfFinished(circuits)    
    print "{0}: {1} >> Finished {2} circuits".format(threading.currentThread().name,math.ceil(time()-start_scan_time),num_finished)
    errors_fd.write("{0}: {1} >> Finished {2} circuits\n".format(threading.currentThread().name,math.ceil(time()-start_scan_time),num_finished))


def getNumberOfFinished(circuits):
    num_of_finished = 0    
    for c_id in circuits:
        if circuits[c_id].state in range(OR_Circuit.RELAY_EXTENDED_RECEIVED,OR_Circuit.DESTROY_OTHER_RECEIVED+1):
            num_of_finished += 1
    return num_of_finished


def wait_nonmain_threads_dead():
    time1 = time()
    time2 = time()
    while True:
        num_of_alive = get_num_of_alive_threads() 
        if num_of_alive == 1: # Only main thread is left
            break
        time2 = time()
        if time2-time1 > SECONDS_TO_CHECK_LIVE_THREADS:
            time1 = time()
            print "We're waiting for {0} non-main threads!".format(num_of_alive-1)

def get_num_of_alive_threads():
    threads = threading.enumerate()
    num_of_alive = 0
    for thread in threads:
        if thread.is_alive():
            num_of_alive += 1  
    return num_of_alive



# This is main function to scan the tor relay
def scan_torrouter(err_fd,routers_list, router_hostname, router_port, maxScanTimeSecs):
    start_scan_torrouter = int(time()) 
    errors_fd = err_fd 
 
    filenames = create_and_save_certs_for_client("some_seed."+router_hostname+"."+str(router_port))
    import socket
    socket.setdefaulttimeout(10)
    orconn = ORConnection()
    print "{0}: Connecting to the server ... ".format(threading.currentThread().name)
    err_fd.write("{0}: Connecting to the server ... \n".format(threading.currentThread().name))
    orconn.connect(router_hostname, router_port, filenames[0], filenames[2],filenames[3])
    print "{0}: Connected!".format(threading.currentThread().name)
    err_fd.write("{0}: Connected!\n".format(threading.currentThread().name))
  
    orconn.socket.setblocking(0)    
    orconn.socket.set_socket_read_timeout(SSL.timeout(sec=10))    ### TODO: think about connectin timeout!
    orconn.socket.set_socket_write_timeout(SSL.timeout(sec=10))    ### TODO: think about connectin timeout!
    circID_start = randint(1000, 3000)
 
    pending_cells = list()
    #pending_cells_buffer = ''
    circuits = dict()
    
    #Fill pending cells list with create cells
    print "{0}: Preparing create cells ... ".format(threading.currentThread().name)
    err_fd.write("{0}: Preparing create cells ... \n".format(threading.currentThread().name))
    fill_with_create_cells(routers_list,pending_cells, circuits, circID_start)
    print "{0}: {1} cells are pending now".format(threading.currentThread().name,len(pending_cells))
    err_fd.write("{0}: {1} cells are pending now\n".format(threading.currentThread().name,len(pending_cells)))
    
    num_to_finish = len(pending_cells)
        
    #start_scan_time = time()
    time_to_scan_left = maxScanTimeSecs - (time()-start_scan_torrouter)
    print "{0}: {1} secs left for scan.".format(threading.currentThread().name,int(time_to_scan_left))
    err_fd.write("{0}: {1} secs left for scan.\n".format(threading.currentThread().name,int(time_to_scan_left)))
    doScan(errors_fd,orconn,pending_cells,circuits,num_to_finish,time_to_scan_left)
    
    #Time to remove temporary key files    
    remove_files(filenames)

    return circuits
    
