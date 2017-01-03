#######################################
####     Configuration   ##############
#######################################
hostname = "dbhost.firebaseio.com"
certs_path = '/etc/ssl/certs/ca-certificates.crt'
port_in = 8888

debug_verbosity = 1
#######################################
####     Dependencies    ##############
#######################################
import ssl
import socket
import datetime
import sys
import thread
import select
import logging
#######################################
####     Internal Vars   ##############
#######################################
port_out = 443
hostneedle = "\r\nHost: "
listen_address = ''
buffer_size = 98304
timeout_secs = 60
#######################################
####     Tools	         ##############
#######################################

def prox_log_ (message, verbosity):
	if (verbosity <= debug_verbosity):
		logging.debug(message)
		print message

def prox_log_header ():
	prox_log_("<=======================>", 1)
	prox_log_("connection #" + str(connection_id), 1)
	prox_log_("Incoming @ " + str(datetime.datetime.now()), 1)
	prox_log_("on: " + str(conn_in.getsockname()), 1)

def prox_log_disconnect (connection_id):
	prox_log_("connection #" + str(connection_id), 1)
	prox_log_("Disconnected", 1)

####	Proxy HTTP Host field	####
def proxy_http_host (msg_in):
	## parse for host
	host_start = msg_in.find(hostneedle)
	if (host_start != -1):
		host_start = msg_in.find(hostneedle) + len(hostneedle)
		host_end = msg_in[host_start:].find("\r\n")
		hostname_old = msg_in[host_start:host_start+host_end]
		prox_log_("Changing Hostname: " + hostname_old, 1)
		prox_log_("To: " + hostname, 1)
		
		msg_ret = msg_in[:host_start] + hostname + msg_in[host_start+host_end:]
		prox_log_(msg_ret, 3)
	else:
		msg_ret = msg_in
	return msg_ret

####################################		
####	HTTP Handler Thread		####
####################################
def handle_http_connection (conn_in, addr, connection_id):
	## log connection
	prox_log_header()
	
	# make new outgoing (TLS) socket
	conn_out = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
	try:
		conn_out.connect((hostname, port_out))
	except:
		print "Error: Cannot make TLS Connection"
		thread._Thread_stop()
	## get TLS Certificate
	cert = conn_out.getpeercert()
	
	## Set sockets to non-blocking
	conn_in.setblocking(0)
	conn_out.setblocking(0)
	## prepare buffers
	msg_in = ""
	msg_out = ""
	
	##### Proxy Connection Endpoints ####
	while True:
		#### Handle Comms  ######################
		ready_to_read, ready_to_write, in_error = select.select([conn_in, conn_out], [], [], timeout_secs)
		#########################################
		#### Incoming Comms  ####################
		#########################################
		## if incoming data ready
		if (conn_in in ready_to_read):
			try:
				## attempt incoming data read
				msg_in = conn_in.recv(buffer_size)
				## handle disconnections
				if (len(msg_in) < 1):
					prox_log_disconnect(connection_id)
					return 0
			except:
				pass
			## if incoming data recieved
			if (len(msg_in) > 0):
				prox_log_("msg in: \n" + msg_in, 2)
				
				msg_in_changed = proxy_http_host(msg_in)
				
				## pass incoming data forward
				try:
					conn_out.sendall(msg_in_changed)
				## or close socket
				except:
						conn_in.shutdown(2)
						break
				msg_in = ""
		#########################################
		#### Outgoing Comms  ####################
		#########################################
		## if outgoing data ready
		if (conn_out in ready_to_read):
			try:
				## attempt outgoing data read
				msg_out = conn_out.recv(buffer_size)
				## handle disconnections
				if (len(msg_out) < 1):
					prox_log_disconnect(connection_id)
					return 0
			except:
				pass
			## if outgoing data recieved
			if (len(msg_out) > 0):
				prox_log_("msg out: \n" + msg_out, 2)
				## pass outgoing data back
				try:
					conn_in.sendall(msg_out)
				## or close socket
				except:
						conn_out.shutdown(2)
						break
				msg_out = ""



#######################################
####	Main			###############
#######################################

#### Setup TLS
context = ssl.create_default_context()
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

## Verify Certificates
try:
	context.load_verify_locations(certs_path)
except Exception, e:
	print "Error: Cannot load certificates " + str(e)
	sys.exit(0)

## Create incoming socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
## Allow rebinding
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
## Bind
try:
	s.bind((listen_address, port_in))
except Exception, e:
	print "Error: Cannot bind " + str(e)
	sys.exit(0)
## Listen
try:
	s.listen(1)
except Exception, e:
	print "Error: Cannot listen " + str(e)
	sys.exit(0)
	

## Handle and track new connections
connection_id = 1;
while True:
	## accept connection
	conn_in, addr = s.accept()
	# launch handler thread
	thread.start_new_thread(handle_http_connection, (conn_in, addr, connection_id))
	connection_id += 1

