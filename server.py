import socket
import select
import queue

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 8000

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SO_ - socket option
# SOL_ - socket option level
# Sets REUSEADDR (as a socket option) to 1 on socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind, so server informs operating system that it's going to use given IP and port
# For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
server_socket.bind((IP, PORT))

# This makes server listen to new connections
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data
clients = {}

# Last message sent from clients - socket as a key, message as data
messages = {}

# Log of the chat room - includes at most 10 last text messages(except commands) of the room
log = queue.Queue(10)

print(f'Listening for connections on {IP}:{PORT}...')

# Handles message receiving
def receive_message(client_socket):

    try:

        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())

        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:

        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

while True:

    # Calls Unix select() system call or Windows select() WinSock call with three parameters:
    #   - rlist - sockets to be monitored for incoming data
    #   - wlist - sockets for data to be send to (checks if for example buffers are not full and socket is ready to send some data)
    #   - xlist - sockets to be monitored for exceptions (we want to monitor all sockets for errors, so we can use rlist)
    # Returns lists:
    #   - reading - sockets we received some data on (that way we don't have to check sockets manually)
    #   - writing - sockets ready for data to be send thru them
    #   - errors  - sockets with some exceptions
    # This is a blocking call, code execution will "wait" here and "get" notified in case any action should be taken
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)


    # Iterate over notified sockets
    for notified_socket in read_sockets:

        # If notified socket is a server socket - new connection, accept it
        if notified_socket == server_socket:

            # Accept new connection
            # That gives us new socket - client socket, connected to this given client only, it's unique for that client
            # The other returned object is ip/port set
            client_socket, client_address = server_socket.accept()

            # Client should send his name right away, receive it
            user = receive_message(client_socket)

            # If False - client disconnected before he sent his name
            if user is False:
                continue

            # Add accepted socket to select.select() list
            sockets_list.append(client_socket)

            # Also save username and username header
            clients[client_socket] = user
            messages[client_socket] = ""

            print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

        # Else existing socket is sending a message
        else:

            # Receive message
            message = receive_message(notified_socket)

            # If False, client disconnected, cleanup
            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

                # Remove from list for socket.socket()
                sockets_list.remove(notified_socket)

                # Remove from our list of users
                del clients[notified_socket]

                continue
            # Get user by notified socket, so we will know who sent the message
            user = clients[notified_socket]
            data=message["data"].decode("utf-8")
            if data == '\n':
                continue
            if data[0] == '<':
                message = 'Received: '+ data + '\nInvalid Command!\nType <HELP> to check all valid commands'
                if data[:10] == "<USERINFO>":
                    print('Received command: USER INFO')
                    message = 'USER INFO:\nUser Name:'+user["data"].decode("utf-8")
                    print(message)

                elif data[:11] == "<LISTUSERS>":
                    print('Received command: USER LIST')
                    message = '\nUser List:\n'
                    for key in clients:
                        print(clients[key]['data'].decode('utf-8'))
                        message = message + clients[key]['data'].decode('utf-8')+'\n'
                    print(message)

                elif data[:8] == "<RENAME>":
                    print('Received command: RENAME')
                    new_name = data[9:].lstrip().encode()
                    new_name_header = f"{len(new_name):<{HEADER_LENGTH}}".encode('utf-8')
                    clients[notified_socket] ={'header': new_name_header, 'data': new_name}
                    message = 'Changed the name of user '+user["data"].decode("utf-8")+ ' to '+ new_name.decode("utf-8")
                    user = clients[notified_socket]
                    print(message)

                elif data[:8] == "<REPEAT>":
                    print('Received command: REPEAT')
                    message = messages[client_socket]
                    if not len(message):
                        message = 'ERROR: Last text message of the user is empty!'
                    print('LAST TEXT MESSAGE IS: '+ message)

                elif data[:5] == "<LOG>":
                    print('Received command: LOG')
                    message = '\nLOG:\n'
                    for text in list(log.queue):
                        message = message + text + '\n'
                    print(message)
                elif data[:6] == "<HELP>":
                    print('Received command: HELP')
                    message = '\nAll valid commands:\n'\
                              '<HELP>: Show all valid commands.\n'\
                              '<LISTUSERS>: List all registered users.\n'\
                              '<LOG>: Display at most last 10 text messages (expect commands) of the chat room.\n'\
                              '<RENAME> + whitespace + (new name): Rename current client.\n'\
                              '<REPEAT>: Repeat last text message from the client.\n'\
                              '<USERINFO>: Show current client\'s user name.\n'
                    print(message)
                message = message.encode()
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                notified_socket.send(user['header'] + user['data'] + message_header + message)


            else:
                print(f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')
                messages[client_socket] = message["data"].decode("utf-8")
                if log.qsize()==10:
                    log.get()
                log.put(user["data"].decode("utf-8") + " > " + messages[client_socket])
                # Iterate over connected clients and broadcast message
                for client_socket in clients:

                    # But don't sent it to sender
                    if client_socket != notified_socket:
                        # Send user and message (both with their headers)
                        # We are reusing here message header sent by sender, and saved username header send by user when he connected
                        client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])

    # It's not really necessary to have this, but will handle some socket exceptions just in case
    for notified_socket in exception_sockets:

        # Remove from list for socket.socket()
        sockets_list.remove(notified_socket)

        # Remove from our list of users
        del clients[notified_socket]