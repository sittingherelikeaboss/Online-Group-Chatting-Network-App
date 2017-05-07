#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import struct

########################################################################
# Echo-Server class
########################################################################

class Server:

    HOSTNAME = socket.gethostname()
    PORT = 50000

    RECV_SIZE = 1024
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Block while waiting for incoming connections. When
                # one is accepted, pass the new socket reference to
                # the connection handler.
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                # until "at least 1 byte or more" is available.
                recvd_bytes = connection.recv(Server.RECV_SIZE)
            
                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed (The other end is probably in
                # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
                # server end of the connection and get the next client
                # connection.
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                # Decode the received bytes back into strings. Then output
                # them.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                print("Received: ", recvd_str)
                
                # Send the received bytes back to the client.
                connection.sendall(recvd_bytes)
                print("Sent: ", recvd_str)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

########################################################################
# Echo-Client class / Echo Receiver class
########################################################################

# YOU ARE WORKING ON THIS FOR LAB 4!!!!!!!!!!!!!!!!!!

class Client: # RECEIVER

    SERVER_HOSTNAME = socket.gethostname()
    RECV_SIZE = 1024

    ############# For IP Multicasting #############

    RECV_SIZE_BROAD = 256

    BIND_ADDRESS_BROAD = "0.0.0.0" # INADDR_ANY
    BIND_ADDRESS_PORT_BROAD = (BIND_ADDRESS_BROAD, Server.PORT)

    ###############################################

    def __init__(self):
        self.connected_to_CRDP = False
        self.username = ''
        self.get_socket()
        #self.connect_to_server()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def create_listen_socket(self): # SENDER for IP Multicast
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Sender.TTL_BYTE)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def broadcast_forever(self):
        try:
            while True:
                self.socket.sendto(Client.MESSAGE_ENCODED, Client.ADDRESS_PORT)
                time.sleep(Client.TIMEOUT)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        while True:
            
            # In this version we keep prompting the user until a non-blank
            # line is entered.
            self.input_text = input("Input: ")
            if self.input_text != '':
                break

        # Deal with Client to Server commands here!
        if self.input_text == "connect" and (not self.connected_to_CRDP):
            # This works
            self.connect_to_server()
            self.connected_to_CRDP = True
            self.connection_send()
            self.connection_receive()
        elif self.input_text[:4] == "name" and self.connected_to_CRDP:
            self.connection_send()
            self.connection_receive()
        elif self.input_text[:4] == "chat" and self.connected_to_CRDP:
            pass
        elif self.input_text[:6] == "create" and self.connected_to_CRDP:
            self.connection_send()
            self.connection_receive()
        elif self.input_text == "list" and self.connected_to_CRDP:
            self.connection_send()
            self.connection_receive()
        elif self.input_text == "bye" and self.connected_to_CRDP:
            # This works
            self.connection_send()
            print()
            print("Closing server connection ...")
            self.socket.close()
            sys.exit(1)
        else:
            print("Invalid input")
    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                #self.connection_send()
                #self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
            # print("Sent: ", self.input_text)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################





