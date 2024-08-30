import os
import sys
from socket import *
import time

from Quic_Api import *
from LinkedList import *

# global variable packet_number_counter initialized to 0
packet_number_counter = 0


# Generate random data for a file of a given size
def generate_random_data(size):
    return os.urandom(size)

# Generate a public_key and private_key for example
client_public_key = "client_public_key".encode('utf-8')
client_private_key = "client_private_key"
symmetric_key = False # Change this to True when client got the server public key

def parse_arguments(argv):
    ip_address = None
    port = None
    times = None

    i = 1
    while i < len(argv):
        if argv[i] == "-ip" and i + 1 < len(argv):
            ip_address = argv[i + 1]
            i += 2
        elif argv[i] == "-p" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
                i += 2
            except ValueError:
                print("Invalid port number.")
                port = None
        elif argv[i] == "-t" and i + 1 < len(sys.argv):
            try:
                times = int(argv[i + 1])
                i += 2
            except ValueError:
                print("Invalid times.")
                times = None
        else:
            print(f"Invalid argument: {argv[i]}")
            i += 1

    return ip_address, port, times

def main():
    attempts = 0
    max_attempts = 5

    while attempts < max_attempts:
        attempts += 1

        # Try to parse the arguments
        ip_address, port, times = parse_arguments(sys.argv)

        # Check if the arguments are valid
        if ip_address is None or port is None or times is None:
            print(f"Attempt {attempts} failed. Please try again.")
            if attempts < max_attempts:
                ip_address = input("Enter IP Address (-ip): ") if not ip_address else ip_address
                port = input("Enter Port (-p): ") if not port else port
                times = input("Enter Times (-t): ") if not times else times

                sys.argv = ["Client.py", "-ip", ip_address, "-p", port, "-t", times]
            continue
        else:
            break

    if attempts == max_attempts:
        print("Too many failed attempts. Exiting.")
        sys.exit(1)

    # Part A : Create file of size 2MB from random data
    file_path = "random_data.txt"
    file_size = 2 * 1024 * 1024
    file_data = generate_random_data(file_size)
    if file_data is None:
        print("Error generating random data.")
        sys.exit(1)

    # Create the file and write to it
    try:
        with open(file_path, "wb") as file:
            file.write(file_data)
    except IOError:
        print("File creation failed")
        sys.exit(1)

    # Read the file
    try:
        with open(file_path, "rb") as file:
            read_data = file.read(file_size)
            if read_data != file_data:
                print("Data read from file does not match the original data.")
                sys.exit(1)
    except IOError:
        print("File open for reading failed.")
        sys.exit(1)


    # Part B : Establish a connection with the server

    # Create a connection ID
    client_cid = generate_cid()

    # Create a socket
    client_socket = socket(AF_INET,SOCK_DGRAM)
    if client_socket is None:
        print("Error creating a socket.")
        sys.exit(1)

    # Connect to the server
    server_address = (ip_address, port)
    client_socket.connect(server_address)
    if client_socket is None:
        print("Error connecting to the server.")
        sys.exit(1)

    # Create a new Packet list to store the RTT values
    client_packet_list = PacketList()

    # Handshake process
    print("Handshake process on the client side started.")
    # Send the first client hello message with the connection ID
    client_hello = send_first_chlo(client_socket, server_address, client_cid)
    if client_hello is False:
        print("Error sending the first CHLO message to the server")
        sys.exit(1)
    send_client_hello_time = time.time()

    # Receive ACK message from the server
    ack_message = receive_ack(client_socket)
    if ack_message != 1:
        print("Error receiving the ACK message from the server.")
        sys.exit(1)
    print("ACK message received from the server.")
    receive_ack_time = time.time()
    client_packet_list.insert(1, receive_ack_time, send_client_hello_time, client_hello)
    packet_number_counter = 1

    # Receive the server Rejection message
    server_rejection = receive_rej(client_socket)
    if server_rejection is False:
        print("Error receiving the server rejection message.")
        sys.exit(1)

    # Save the server connection ID
    server_cid = server_rejection

    # Send ACK message to the server
    ack_message = send_ack(client_socket, server_address, server_cid,1)
    if ack_message is False:
        print("Error sending the ACK message to the server.")
        sys.exit(1)
    print("ACK message sent to the server.")

    # Send the second client hello message with the server connection ID and public key and times to send the file
    client_hello2 = send_complete_chlo(client_socket, server_address, client_cid, server_cid, client_public_key, times)
    if client_hello2 is False:
        print("Error sending the second CHLO message to the server.")
        sys.exit(1)
    send_client_hello2_time = time.time()

    # Receive the ACK message from the server
    ack_message = receive_ack(client_socket)
    if ack_message != 2:
        print("Error receiving the ACK message from the server for packet 2.")
        sys.exit(1)
    print("ACK message received from the server.")
    receive_ack2_time = time.time()
    client_packet_list.insert(2, receive_ack2_time, send_client_hello2_time, client_hello2)
    packet_number_counter = 2

    # Receive the server hello message with the server public key
    server_public_key = receive_shlo(client_socket)
    if server_public_key is False:
        print("Error receiving the server SHLO message.")
        sys.exit(1)
    symmetric_key = True
    print("Symmetric key established")

    # Send the ACK message to the server
    ack_message = send_ack(client_socket, server_address, server_cid, 2)
    if ack_message is False:
        print("Error sending the ACK message to the server.")
        sys.exit(1)
    print("ACK message sent to the server.")

    print("Handshake process on the client side is complete.")

    # Part C : Send the file to the server number of times
    print(f"Sending the file to the server {times} times.")
    for i in range(times):
        # Send the file to the server
        packet_number_counter = send_file(client_socket, server_address, server_cid, file_path, client_packet_list, symmetric_key)
        if packet_number_counter is False:
            print("Error sending the file to the server.")
            sys.exit(1)
        print(f"File sent to the server {i + 1} times.")

    # Send close message to the server
    packet_number_counter += 1
    close_message = send_close(client_socket, server_address, server_cid, packet_number_counter)
    if close_message is False:
        print("Error sending the close message to the server.")
        sys.exit(1)
    sent_close_time = time.time()

    # Receive the ACK message from the server
    ack_message = receive_ack(client_socket)
    if ack_message != packet_number_counter:
        print("Error receiving the ACK message from the server for the close message.")
        sys.exit(1)
    print("ACK message received from the server.")
    receive_ack3_time = time.time()
    client_packet_list.insert(packet_number_counter, receive_ack3_time, sent_close_time, close_message)

    # Part D : Calculate the RTT values
    # Smoothed RTT = (1 - ALPHA) * Smoothed RTT + ALPHA * Sample RTT (already calculated)
    # RTT Variance = (1 - BETA) * RTT Variance + BETA * |Smoothed RTT - Sample RTT| (already calculated)
    client_packet_list.calculate_min_rtt()
    print("Creating the graph of the RTT values.")
    client_packet_list.create_graph("RTT Values")

    # Close the socket
    client_socket.close()
    print("Client Socket closed.")

    # Delete the file
    os.remove(file_path)
    print("File deleted.")


if __name__ == "__main__":
    main()





































