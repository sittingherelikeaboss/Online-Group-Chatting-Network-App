#!/usr/bin/env python3

########################################################################

import socket
import argparse
import time
import sys
import base64
import select
import random
import queue
import struct

from EchoClientServer import Client

########################################################################
# SERVER / Broadcast Server class / SENDER
########################################################################

# YOU ARE WORKING ON THIS FOR LAB 4!!!!!!!!!!!!!!!!!!!

class Server: # SENDER

    HOSTNAME = socket.gethostname()
    PORT = 50000 # Chat Room Directory Port

    BACKLOG = 5
    RECV_SIZE = 1024

    # Use a zero byte to encode the end of the message. It is not a
    # valid Base64 encoding output.
    EOM_BYTE = b"\0"

    MSG_ENCODING = "utf-8"

    ############# For IP Multicasting #############

    TIMEOUT_BROAD = 2
    RECV_SIZE_BROAD = 256
    BACKLOG_BROAD = 10
    
    MESSAGE =  HOSTNAME + " multicast beacon: "
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

##    MULTICAST_ADDRESS = "239.0.0.10"
    MULTICAST_ADDRESS = ""
    PORT_BROAD = 2000
##    ADDRESS_PORT = (MULTICAST_ADDRESS, PORT_BROAD)
    ADDRESS_PORT = ()

    TTL = 1
    TTL_BYTE = struct.pack('B', TTL)

    ###############################################

    def __init__(self):
        self.username = ''
        self.chatroom = {}
        
        self.get_socket()
        self.receive_forever()

    def __init__(self):
        self.create_listen_socket()
        self.set_select_lists()
        self.process_connections_forever()

    def set_select_lists(self):
        ################################################################
        # Set the initial lists of read and write sockets that will be
        # passed to the select module. Initially, the read_list will
        # contain only the listen socket that we create.
        ################################################################
        self.read_list = [self.listen_socket]
        self.write_list = []

    def get_random_encoded_msg_bytes(self):
        msg = random.choice(StringSamples.MSG_LIST)
        msg_bytes = msg.encode(Server.MSG_ENCODING)
        msg_bytes_base64 = base64.b64encode(msg_bytes)
        return(msg_bytes_base64 + Server.EOM_BYTE)

    def create_listen_socket(self):
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind((Server.HOSTNAME, Server.PORT))
            self.listen_socket.listen(Server.BACKLOG)
            print("Chat Room Directory Server listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        ################################################################
        # Define a dictionary of message queues. The dictionary keys
        # will be the sockets associated with the message queues.
        ################################################################
        self.message_queues = {}

        try:
            while True:
                ########################################################
                # Get the current lists of read, write and exception
                # ready sockets from the select module.
                ########################################################
                read_ready, write_ready, except_ready = select.select(
                    self.read_list, self.write_list, [])

                # Iterate through the read ready sockets, processing
                # each one in turn.
                for read_socket in read_ready:
                    if read_socket is self.listen_socket:
                        # If the read socket is the listen socket, it
                        # means that there is a new client
                        # connection. Accept it and then append the
                        # client socket to the read_list.
                        client, address = read_socket.accept()
                        print("-" * 72)
                        print("Client connection has occured on {}.".format(address))
                        client.setblocking(0)
                        self.read_list.append(client)

                        ################################################
                        # Create a new message queue for the new
                        # client. Use the client socket as the
                        # message_queues dictionary key.
                        ################################################
                        self.message_queues[client] = queue.Queue()
                    else:
                        # If the read_socket is not the listen socket,
                        # then it must be a client socket. Read from
                        # the client for input and if it is valid,
                        # place it into its associated message queue.
                        recv_bytes = read_socket.recv(Server.RECV_SIZE)
                        recv_string = recv_bytes.decode(Server.MSG_ENCODING)

                        if len(recv_bytes):
                            ############################################
                            # If data came in on the client socket, put
                            # the data into the client message queue.
                            ############################################

                            if recv_string == "bye":
                                print("Closing client connection ... ")
                                del self.message_queues[read_socket]
                                self.read_list.remove(read_socket)
                                read_socket.close()
                                continue # SKIP ALL THE EXECUTION BELOW THIS

##                            print("1", recv_string)
                            self.client_to_server_commands(recv_string)
                            
                            self.message_queues[read_socket].put(recv_bytes)

                            # Make sure that this socket is on the
                            # write_list so that we can echo the data
                            # back to the client.
                            if read_socket not in self.write_list:
                                #print("Adding read_socket to write_list: ", read_socket)
                                self.write_list.append(read_socket)
                        else:
                            ############################################
                            # If no data was read from the client
                            # socket, the other end has closed. Delete
                            # the message queue for this client,
                            # remove the socket from the read list,
                            # then close the socket on this end.
                            ############################################
                            print("Closing client connection ... ")
                            del self.message_queues[read_socket]
                            self.read_list.remove(read_socket)
                            read_socket.close()

                ########################################################
                # Iterate through the write ready socket list,
                # processing each one in turn. If there is something
                # there, it is a client waiting for its echo
                # response. Send the top entry in the message queue
                # for that socket.
                ########################################################
                for write_socket in write_ready:
                    try:
                        ################################################
                        # get_nowait will generate a queue.Empty
                        # exception if the message queue is
                        # empty. When that is the case, remove this
                        # socket from the write_list. Otherwise, echo
                        # the message.
                        ################################################
                        next_msg = self.message_queues[write_socket].get_nowait()
                        
                        print("sending msg = ", next_msg)
                        write_socket.sendall(next_msg)
                            
                    except queue.Empty as msg:
                        #print("Removing socket from write_list: ", write_socket)
                        self.write_list.remove(write_socket)

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.listen_socket.close()

    def client_to_server_commands(self, message):
##        print("2", message) 
        if message == "list":
            self.CRD()
        elif message[:6] == "create":
##            print("3") # Uncomment for debugging CREATE
            self.get_chatroom_info(message)
            self.create_room()
        elif message[:6] == "delete":
            pass
        elif message[:6] == "replay":
            pass

##    def create_room(self):
##        try:
##            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
##            self.socket.bind(Client.BIND_ADDRESS_PORT)
##
##            ############################################################
##            # multicast_request must contain a bytes object consisting
##            # of 8 bytes. The first 4 bytes are the multicast group
##            # address. The second 4 bytes are the interface address to
##            # be used. An all zeros I/F address means all network
##            # interfaces.
##            ############################################################
##                        
##            multicast_group_bytes = socket.inet_aton(Sender.MULTICAST_ADDRESS)
##
##            # We can use the following two statements:
##            multicast_if_bytes = socket.inet_aton(Receiver.BIND_ADDRESS)
##            multicast_request = multicast_group_bytes + multicast_if_bytes
##
##            # Or, if we want all interfaces we could use:
##            # multicast_request = struct.pack("4sl", multicast_group_bytes, socket.INADDR_ANY)
##
##            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
##
##        except Exception as msg:
##            print(msg)
##            sys.exit(1)

    def get_chatroom_info(self, message):
##        print("4") # Uncomment for debugging CREATE
        numSpace = 0
        chatroom_name = ''
        ip_multicast_addr = ''
        port_multicast = ''
        for char in message[7:]:
##            print(char)
            if char == ' ':
                numSpace += 1
            if numSpace == 0:
                chatroom_name += char
            elif numSpace == 1:
                ip_multicast_addr += char
            elif numSpace == 2:
                port_multicast += char
        # Insert dictionary in LIST of CHAT ROOM DIRECTORY
##        self.chatroom.append({'Chatroom Name': chatroom_name, 'Address': ip_multicast_addr, 'Port': port_multicast})
##        print("5", chatroom_name, ip_multicast_addr,
##              port_multicast) # Uncomment for debugging CREATE
        self.chatroom = {'Chatroom Name': chatroom_name, 'Address': ip_multicast_addr, 'Port': port_multicast}
##        print("6") # Uncomment for debugging CREATE
        self.CRD()

    def CRD(self): # Returns a copy of the current chat room directory
##        print("7") # Uncomment for debugging CREATE
        print("Chatroom Name:", self.chatroom['Chatroom Name'],
              "Address:", self.chatroom['Address'],
              "Port:", self.chatroom['Port'])

    def set_select_lists_broad(self):
        ################################################################
        # Set the initial lists of read and write sockets that will be
        # passed to the select module. Initially, the read_list will
        # contain only the listen socket that we create.
        ################################################################
        self.read_list_broad = [self.listen_socket_broad]
        self.write_list_broad = []

    def create_CRD(self): # Create Chat Room Directory
        # Use administratively scoped IP multicast range 239.0.0.0 to 239.255.255.255
        pass
        
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





