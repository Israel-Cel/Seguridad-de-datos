
"""
Primer Script TCP Client
"""

import socket

target_host = " www.google.com "
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client
client.connect((target_host, target_port))

# send some data
client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

# receive some data
response = client.recv(4096)

print(response.decode())

client.close()

"""
Segundo Script UDP CLIENT
"""

import socket

target_host = "127.0.0.1"
target_port = 9997

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send some data
client.sendto(b"AAABBBCCC", (target_host, target_port))

# receive some data
data, addr = client.recvfrom(4096)

print(data.decode())

client.close()

"""
Tercer Script TCP SERVER
"""

import socket
import threading

IP = "0.0.0.0"
PORT = 9998

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)
    print(f' [*] Listening on {IP}: {PORT}')

    while True:
        client, address = server.accept()
        print(f' [*] Accepted connection from {address[0]}: {address[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,))
         client_handler.start():

            def handle_client(client_socket): 5
                with client_socket as sock:
                    request = sock.recv(1024)
                    print(f' [*] Received: (request.decode("utf-8") }')
                    sock.send(b'ACK')

if __name__ == "__main__":
    main()

"""
Cuarto Script Replacing NETCAT
"""

import sys
import socket
import getopt
import threading
import subprocess

# define some global variables
listen             = False
command            = False
upload             = False
execute            = ""
target             = ""
upload_destination = ""
port               = 0

def usage():
    print "BHP Net Tool"
    print
    print "Usage: bhpnet.py -t target_host -p port"
    print "-l --listen              - listen on [host]:[port] for incoming connections"
    print "-e --execute=file_to_run - execute the given file upon receiving a connection"
    print "-c --command             - initialize a command shell"
    print "-u --upload=destination  - upon receiving connection upload a file and write to [destination]"
    print
    print
    print "Examples: "
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -c"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135"
    sys.exit(0)

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", 
        ["help","listen","execute","target","port","command","upload"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

    # are we going to listen or just send data from stdin?
    if not listen and len(target) and port > 0:
        buffer = sys.stdin.read()
        client_sender(buffer)

    if listen:
        server_loop()

def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to our target host
        client.connect((target, port))

        if len(buffer):
            client.send(buffer)

        while True:
            recv_len = 1
            response = ""

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data

                if recv_len < 4096:
                    break

            print response,

            buffer = raw_input("")
            buffer += "\n"

            client.send(buffer)

    except:
        print "[*] Exception! Exiting."
        client.close()

def server_loop():
    global target

    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()

def run_command(command):
    command = command.rstrip()

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command.\r\n"

    return output

def client_handler(client_socket):
    global upload
    global execute
    global command

    if len(upload_destination):
        file_buffer = ""

        while True:
            data = client_socket.recv(1024)

            if not data:
                break
            else:
                file_buffer += data

        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
        except:
            client_socket.send("Failed to save file to %s\r\n" % upload_destination)

    if len(execute):
        output = run_command(execute)
        client_socket.send(output)

    if command:
        while True:
            client_socket.send("<BHP:#> ")
            cmd_buffer = ""

            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            response = run_command(cmd_buffer)
            client_socket.send(response)

main()

"""
Quinto Scrip Proxi
"""

import sys
import socket
import threading
def server_loop(local_host,local_port,remote_host,remote_port,receive_first):

	server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

	try:
		server.bind((local_host,local_port))
	except:
			print "[!!] Failed to listen on $s:$d" % (local_host,local_port)
			print "[!!] Check for other listening sockets or correct permissions."
			sys.exit(0)
	print "[*] Listening on $s:$d" % (local_host,local_port)

	server.listen(5)

	while True:
			client_socket, addr = server.accept()

			# print out the local connection information
			print "[==>] Received incoming connection from %s:%d" % (addr[0],addr[1])

			# start a thread to talk to the remote host
			proxy_thread = threading.Thread(target=proxy_handler,args=(client_socket,remote_host,remote_port,receive_first))

			proxy_thread.start()

def main():

	# no fancy command-line parsing here
	if len(sys.argv[1:]) != 5:
		print "Usage: ./tcpproxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]"
		print "Example: ./tcpproxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
		sys.exit(0)

	# setup local listening parameters
	local_host = sys.argv[1]
	local_port = int(sys.argv[2])

	# setup remote target
	remote_host = sys.argv[3]
	remote_port = int(sys.argv[4])

	# this tells our proxy to connect and receive data
	# before sending to the remote host
	receive_first = sys.argv[5]

	if "True" in receive_first:
		receive_first = True
	else:
		receive_first = False


	# now spin up our listening socket
	server_loop(local_host,local_port,remote_host,remote_port,receive_first)

main()

def proxy_handler(client_socket, remote_host, remote_port, receive_first):

	# connect to the remote host
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# receive data from the remote end if necessary
	if receive_first:

		remote_buffer = receive_from(remote_socket)
		hexdump(remote_buffer)

		# send it to our response handler
		remote_buffer = response_handler(remote_socket)

		# if we have data to send to our local client, send it
		if len(remote_buffer):
			print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
			client_socket.send(remote_buffer)
	# now lets loop and read from local,
		# send to remote, send to local
	# rinse, wash, repeat
	while True:

		# read from local host
		local_buffer = receive_from(client_socket)


		if len(local_buffer):

			print "[==>] Received %d bytes from localhost." % len(local_buffer)
			hexdump(local_buffer)

			# send it to our request handler
			local_buffer = request_handler(local_buffer)

			# send off the data to the remote host
			remote_socket.send(local_buffer)
			print "[==>] Sent to remote."

			# receive back to response
			remote_buffer = receive_from(remote_socket)

			if len(remote_buffer):

				print "[<==] Received %d bytes from remote." % len(remote_buffer)
				hexdump(remote_buffer)

				# send to our response handler
				remote_buffer = response_handler(remote_buffer)

				# send the response to the local socket
				client_socket.send(remote_buffer)

				print "[<==] Sent to localhost."

			# if no more data on either side, close the connections
			if not len(local_buffer) or not len(remote_buffer):
				client_socket.close()
				remote_socket.close()
				print "[*] No more data. Closing connections."

				break

# this is a pretty hex dumping function directly taken from
# the comments here:
# http://code.activestate.com/recipes/142812-hex-dumper/
def hexdump(src, length=16):
	result = []
	digits = 4 if isinstance(src, unicode) else 2

	for i in xrange(0, len(src), length):
		s = sr[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b''join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
		result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )

	print b'\n'.join(result)

def receive_from(connection):

	buffer = ""

	# We set a 2 second timeout; depending on your
	# target, this may need to be adjusted
	connection.settimeout(2)

		try:
			# keep reading into the buffer until
			# there's no more data
			# or we time out
			while True:
				data = connection.recv(4096)

				if not data:
					break

				buffer += data

		except:
		pass

		return buffer

# modify any requests destined for the remote host
def request_handler(buffer):
	# perform packet modifications
	return buffer

# modify any response destined for the local host
def response_handler(buffer):
	# perform packet modifications
	return buffer