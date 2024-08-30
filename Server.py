from socket import *
import sys
import time

from Quic_Api import *
from LinkedList import *

# Generate a public_key and private_key for example
server_public_key = "server_public_key".encode('utf-8')
server_private_key = "server_private_key"
symmetric_key = False # Change this to True when client got the server public key

def parse_server_arguments(argv):
    port = None

    i = 1
    while i < len(argv):
        if argv[i] == "-p" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
                i += 2
            except ValueError:
                print("Invalid port number.")
                port = None
        else:
            print(f"Invalid argument: {argv[i]}")
            i += 1

    return port

def main ():
    attempts = 0
    max_attempts = 5

    while attempts < max_attempts:
        attempts += 1

        # Try to parse the arguments
        port = parse_server_arguments(sys.argv)

        # Check if the arguments are valid
        if port is None:
            print(f"Attempt {attempts} failed. Please try again.")
            if attempts < max_attempts:
                port = input("Enter Port (-p): ") if not port else port

                sys.argv = ["Server.py", "-p", port]
            continue
        else:
            break

    if attempts == max_attempts:
        print("Too many failed attempts. Exiting.")
        sys.exit(1)

    # If we reach here, it means the arguments are valid
    print(f"Port: {port}")

    # Create file path to store the received files
    file_path = "Received_Files" # Folder name
    try:
        os.mkdir(file_path) # Create the folder
    except FileExistsError:
        pass

    # Part A: Create a UDP socket
    server_packet_list = PacketList()
    # Create a connection ID
    server_cid = generate_cid()
    try:
        server_socket = socket(AF_INET, SOCK_DGRAM)
    except error as e:
        print("Error creating the socket: ", e)
        sys.exit(1)

    server_address = ('', port)

    try:
        server_socket.bind(server_address) # Bind the socket to the address
    except error as e:
        print("Error binding the socket: ", e)
        sys.exit(1)

    print(f"Server is listening on port {port}")

    # Part B: Handshake with the client
    # Receive the first client hello message
    client_cid, client_address = receive_first_chlo(server_socket)
    if not client_cid:
        print("Error receiving the first CHLO message.")
        sys.exit(1)

    # Send the client ACK message
    ack_message = send_ack(server_socket, client_address, client_cid, 1)
    if ack_message is False:
        print("Error sending the ACK message.")
        sys.exit(1)
    print("ACK message sent to the client.")

    # Send the server REJ message
    rej_message = send_rej(server_socket, client_address,server_cid, client_cid)
    if rej_message is False:
        print("Error sending the REJ message.")
        sys.exit(1)
    send_rej_time = time.time()

    # Receive ACK message from the client
    ack_message = receive_ack(server_socket)
    if ack_message != 1:
        print("Error receiving the ACK message from the client for packet 1.")
        sys.exit(1)
    print("Received the ACK message from the client.")
    receive_ack_time = time.time()
    server_packet_list.insert(1, receive_ack_time, send_rej_time, rej_message)

    # Receive second client hello message
    client_hello, times = receive_complete_chlo(server_socket)
    if client_hello is False:
        print("Error receiving the second CHLO message.")
        sys.exit(1)
    symmetric_key = True
    print("Symmetric key is established.")

    # Send ACK message to the client
    ack_message = send_ack(server_socket, client_address, client_cid, 2)
    if ack_message is False:
        print("Error sending the ACK message.")
        sys.exit(1)
    print("ACK message sent to the client.")

    # Send the server hello message
    server_hello = send_shlo(server_socket, client_address, server_cid, client_cid, server_public_key)
    if server_hello is False:
        print("Error sending the SHLO message.")
        sys.exit(1)
    send_shlo_time = time.time()

    # Receive the ACK message from the client
    ack_message = receive_ack(server_socket)
    if ack_message != 2:
        print("Error receiving the ACK message.")
        sys.exit(1)
    print("Received the ACK message from the client.")
    receive_ack2_time = time.time()
    server_packet_list.insert(2, receive_ack2_time, send_shlo_time, server_hello)
    print("Handshake process on the server side is complete.")

    # Part C: Receive the file from the client number of times
    print(f"Receiving the file from the client {times} times.")
    for i in range(times):
        # Generate the file name
        file_name = f"file_{i+1}.dat"
        full_file_path = os.path.join(file_path, file_name) # Full path to the file

        # Receive the file from the client
        success = receive_file(server_socket, full_file_path, client_address) # Save the file in the folder
        if not success:
            print("Not Success: Error receiving the file from the client.")
            sys.exit(1)
        print(f"Received the file {file_name} from the client {times} times.")

    # Receive close message from the client
    close_message = receive_close(server_socket)
    if close_message is False:
        print("Error receiving the close message.")
        sys.exit(1)

    # Send the last ACK message from the client
    ack_message = send_ack(server_socket, client_address, client_cid, close_message)
    if ack_message is False:
        print("Error sending the ACK message.")
        sys.exit(1)
    print("Last ACK message sent to the client.")

    # Calculate the RTT values
    # Smoothed RTT = (1 - ALPHA) * Smoothed RTT + ALPHA * Sample RTT (already calculated)
    # RTT Variance = (1 - BETA) * RTT Variance + BETA * |Smoothed RTT - Sample RTT| (already calculated)
    server_packet_list.calculate_min_rtt()


   # Create fake delays in seconds for the RTT experiment
    delays = [0.1, 0.2, 0.15, 0.3, 0.25]

    fake_packet_list = PacketList()
    simulate_network_conditions(fake_packet_list, delays)

    print("RTT Experiment: creating the graph of the RTT values with the fake delays.")
    fake_packet_list.create_graph("RTT Experiment")

    # Close the server socket
    server_socket.close()
    print("Server is closed.")

    # Delete the received files and the folder
    for file in os.listdir(file_path):
        os.remove(os.path.join(file_path, file))
    os.rmdir(file_path)


if __name__ == "__main__":
    main()














