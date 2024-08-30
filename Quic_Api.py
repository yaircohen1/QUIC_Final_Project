import struct
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time

from LinkedList import *

# CONSTANTS
QUIC_VERSION = 1
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
BUFFER_SIZE = 2048

# QUIC Packet Types
INITIAL_REQUEST = 0x00
INITIAL_COMPLETE = 0x01
REJ = 0x02
HANDSHAKE_DONE = 0x03

# QUIC Frame Types
ACK = 0x05
DATA = 0x06
CLOSE = 0x07
FCHLO = 0x08
SCHLO = 0x09
SHLO = 0x0A

# QUIC Key for encryption/decryption (just for testing purposes)
quic_key_symmetric = bytes.fromhex('866dccdafb8c6ccaebfe386af9d38f99ed44c4644c3be3531b6ded534b961e75')
low_key = bytes.fromhex('86cabf595597c45019bf22f167417a7bf2051a9933909e8ea698a26b59c54e76')
ack_key = bytes.fromhex('0fc5e05f1ca293a8b22fbb1ec4778d8ce133b6300ba08e139298b41c7a2816b0')

# Function to encrypt data
def encrypt(data, nonce, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()) # Create a cipher object (c
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, encryptor.tag

# Function to decrypt data
def decrypt(nonce, ciphertext, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Function to generate a CID
def generate_cid():
    return os.urandom(8)  # 8 bytes for CID

# Function to build a QUIC frame
def build_frame(frame_type, stream_id, offset, data):
    data_length = len(data)
    frame_header = struct.pack('!B', frame_type)
    frame_header += struct.pack('!I', stream_id)
    frame_header += struct.pack('!Q', offset)
    frame_header += struct.pack('!H', data_length)
    return frame_header + data

# Function to parse a QUIC frame
def parse_frame(frame):
    frame_type = frame[0]
    stream_id = struct.unpack('!I', frame[1:5])[0]
    offset = struct.unpack('!Q', frame[5:13])[0]
    data_length = struct.unpack('!H', frame[13:15])[0]
    data = frame[15:15+data_length]
    return frame_type, stream_id, offset, data


# Function to build a QUIC long header packet
def build_long_header_packet(packet_type, type_specific_bits, version, dest_cid, source_cid, packet_number, frames):
    header_form = 1  # Long header
    fixed_bit = 1  # Always set to 1 for valid packets
    long_packet_type = packet_type & 0x3  # Use 2 bits for packet type
    type_specific = type_specific_bits & 0xF  # Use 4 bits for type-specific
    first_byte = (header_form << 7) | (fixed_bit << 6) | (long_packet_type << 4) | type_specific

    dest_cid_len = len(dest_cid)
    source_cid_len = len(source_cid)

    # Build the long header
    header = struct.pack(
        '!BIBB',
        first_byte,
        version,
        dest_cid_len,
        source_cid_len
    ) + dest_cid + source_cid

    # Packet number in the long header
    header += struct.pack('!I', packet_number)

    # Generate a nonce
    nonce = os.urandom(NONCE_SIZE)

    # Encrypt the payload
    for frame in frames:
        if not isinstance(frame, bytes):
            raise TypeError(f"Expected bytes, got {type(frame).__name__}")
    payload = b''.join(frames)
    ciphertext, tag = encrypt(payload, nonce, low_key)

    # Concatenate the header with the encrypted payload
    packet = header + nonce + ciphertext + tag
    return packet

# Function to parse a QUIC long header packet
def parse_long_header_packet(packet):
    offset = 0

    # Extract first byte and parse header fields
    first_byte = packet[offset]
    offset += 1

    header_form = (first_byte >> 7) & 0x1
    fixed_bit = (first_byte >> 6) & 0x1
    long_packet_type = (first_byte >> 4) & 0x3
    type_specific_bits = first_byte & 0xF

    # Extract version, dest_cid_len, and source_cid_len
    version, dest_cid_len, source_cid_len = struct.unpack('!IBB', packet[offset:offset + 6])
    offset += 6

    # Extract dest_cid
    dest_cid = packet[offset:offset + dest_cid_len]
    offset += dest_cid_len

    # Extract source_cid
    source_cid = packet[offset:offset + source_cid_len]
    offset += source_cid_len

    # Extract packet_number
    packet_number = struct.unpack('!I', packet[offset:offset + 4])[0]
    offset += 4

    # Extract nonce
    nonce = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    # Extract tag
    tag = packet[-TAG_SIZE:]

    # Extract ciphertext
    ciphertext_end = len(packet) - TAG_SIZE
    ciphertext = packet[offset:ciphertext_end]

    # Decrypt payload
    payload = decrypt(nonce, ciphertext, tag, low_key)

    # Parse the frames
    frames = []
    offset = 0
    while offset < len(payload):
        frame_type, stream_id, frame_offset, data = parse_frame(payload[offset:])
        frames.append((frame_type, stream_id, frame_offset, data))
        offset += 15 + len(data)  # move to the next frame

    return long_packet_type, version, dest_cid, source_cid, packet_number, frames

# Function to build a QUIC short header packet
def build_short_header_packet(dest_cid, packet_number, frames, key_phase, spin_bit):
    # Generate a nonce
    nonce = os.urandom(NONCE_SIZE)

    # Encrypt the payload (frames combined)
    payload = b''.join(frames)
    if key_phase == 0:
        ciphertext, tag = encrypt(payload, nonce, ack_key)
    else:
        ciphertext, tag = encrypt(payload, nonce, quic_key_symmetric)

    # Packet Number Length (Assuming 2 bytes, for example)
    packet_number_length = 2  # 2 bits for length representation, meaning Packet Number is 2 bytes

    # Build the first byte of the header
    header_form = 0  # Short Header (1 bit)
    fixed_bit = 1    # Valid packet (1 bit)
    reserved_bits = 0  # Must be zero (2 bits)
    key_phase_bit = key_phase  # (1 bit)
    first_byte = (
        (header_form << 7) |
        (fixed_bit << 6) |
        (spin_bit << 5) |
        (reserved_bits << 3) |
        (key_phase_bit << 2) |
        (packet_number_length & 0x3)
    )

    # Build the short header
    header = struct.pack(
        '!B16sH',
        first_byte,
        dest_cid,
        packet_number
    )

    # Concatenate the header with the encrypted payload
    packet = header + nonce + ciphertext + tag
    return packet

# Function to parse a QUIC short header packet
def parse_short_header_packet(packet):
    # Parse the first byte of the header
    first_byte = packet[0]
    header_form = (first_byte >> 7) & 0x1
    fixed_bit = (first_byte >> 6) & 0x1
    spin_bit = (first_byte >> 5) & 0x1
    key_phase = (first_byte >> 2) & 0x1
    packet_number_length = first_byte & 0x3  # Extracts the last 2 bits

    # Parse the remaining part of the header
    dest_cid = packet[1:17]  # Assuming 16 bytes for DCID
    packet_number = struct.unpack('!H', packet[17:17 + packet_number_length])[0]  # Extract packet number based on length

    # Extract nonce, ciphertext, and tag
    nonce = packet[17 + packet_number_length:29 + packet_number_length]  # 12 bytes for nonce
    ciphertext = packet[29 + packet_number_length:-TAG_SIZE]
    tag = packet[-TAG_SIZE:]

    # Decrypt the payload
    if key_phase == 0:
        payload = decrypt(nonce, ciphertext, tag, ack_key)
    else:
        payload = decrypt(nonce, ciphertext, tag, quic_key_symmetric)

    # Parse the frames
    frames = []
    offset = 0
    while offset < len(payload):
        frame_type, stream_id, frame_offset, data = parse_frame(payload[offset:])
        frames.append((frame_type, stream_id, frame_offset, data))
        offset += 15 + len(data)  # move to the next frame

    return header_form, fixed_bit, spin_bit, key_phase, dest_cid, packet_number, frames

# Function to send ACK packet
def send_ack(socket, address, dest_cid, packet_number):
    ack_frame = build_frame(ACK, 0, 0, b'')  # ACK frame
    short_packet = build_short_header_packet(dest_cid, packet_number, [ack_frame], 0, 0)
    packet_size = len(short_packet)
    sent_ack = socket.sendto(short_packet, address)
    if sent_ack != len(short_packet):
        return False
    return packet_size

# Function to send data
def send_data(client_socket, server_address, packet_number, data, dest_cid):
    # Split the data into 5 frames
    frame_size = len(data) // 5
    frames = []

    for i in range(5):
        start = i * frame_size
        end = start + frame_size if i < 4 else len(data)
        frame_data = data[start:end]
        data_frame = build_frame(DATA, 0, i * frame_size, frame_data)  # Data frame
        frames.append(data_frame)

    short_packet = build_short_header_packet(dest_cid, packet_number, frames, 1, 0)

    # Send the packet to the server
    packet_size = len(short_packet)
    sent_data = client_socket.sendto(short_packet, server_address)
    if sent_data != packet_size:
        return False

    return packet_size


# Function to receive data
def receive_data(socket):
    data, _ = socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the server.")
        return False
    header_form, fixed_bit, spin_bit, key_phase, dest_cid, packet_number, frames = parse_short_header_packet(data)
    return frames, dest_cid, packet_number

# Function to receive ACK
def receive_ack(socket):
    data, _ = socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the server.")
        return False
    _, _, _, _, _, packet_number, frames = parse_short_header_packet(data)
    if frames[0][0] != ACK:
        print("Error: Expected ACK frame from the server")
        return False
    return packet_number

# Handshake functions
# Function to send the first message 'ClientHello' to the server
def send_first_chlo(client_socket, server_address, client_cid):
    chlo_frame = build_frame(FCHLO, 0, 0, b'')  # ClientHello frame
    chlo_packet = build_long_header_packet(INITIAL_REQUEST, 0x00, QUIC_VERSION, b'\x00' * 16, client_cid, 1, [chlo_frame])
    packet_size = len(chlo_packet)
    sent_first_chlo = client_socket.sendto(chlo_packet, server_address)
    if sent_first_chlo != len(chlo_packet):
        return False
    print("Sent the first message 'CHLO' to the server")
    return packet_size

# Function to receive the second message 'REJ' from the server
def receive_rej(client_socket):
    data, _ = client_socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the server.")
        return False
    long_packet_type, version, dest_cid, source_cid, packet_number, frames = parse_long_header_packet(data)
    if long_packet_type != REJ:
        print("Error: Expected 'REJ' packet from the server")
        return False
    print("Received message 'REJ' from the server")
    # we got this message from the server, so we can extract the server's connection ID
    return source_cid


# Function to send the complete message 'ClientHello' to the server
def send_complete_chlo(client_socket, server_address, client_cid, server_cid, client_public_key, times):
    # Build the complete CHLO frames with the public key and int times client wants to send the file to the server
    complete_chlo_frame = build_frame(SCHLO, 0, 0, client_public_key + struct.pack('!I', times))
    full_chlo_packet = build_long_header_packet(INITIAL_COMPLETE, 0x00, QUIC_VERSION, server_cid, client_cid, 2, [complete_chlo_frame])
    packet_size = len(full_chlo_packet)
    sent_complete_chlo = client_socket.sendto(full_chlo_packet, server_address)
    if sent_complete_chlo != len(full_chlo_packet):
        return False
    print("Sent the complete message 'CHLO' to the server")
    return packet_size

# Function to receive the third message 'SHLO' from the server
def receive_shlo(client_socket):
    data, _ = client_socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the server.")
        return False

    long_packet_type, version, dest_cid, source_cid, packet_number, frames = parse_long_header_packet(data)
    if long_packet_type != HANDSHAKE_DONE:
        print("Error: Expected 'SHLO' packet from the server")
        return False

    # Extract the server's public key from the frames
    server_public_key = frames[0][3]
    print("Received message 'SHLO' from the server")
    return server_public_key

# Function to receive the first message 'ClientHello' from the client
def receive_first_chlo(server_socket):
    data, address = server_socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the client.")
        return False
    long_packet_type, version, dest_cid, source_cid, packet_number, frames = parse_long_header_packet(data)
    if long_packet_type != INITIAL_REQUEST:
        print("Error: Expected 'CHLO' packet from the client")
        return False
    print("Received the first message 'CHLO' from the client")
    return source_cid, address

# Function to send the message 'REJ' to the client
def send_rej(server_socket, address, server_cid, client_cid):
    rej_frame = build_frame(REJ, 0, 0, b'')
    rej_packet = build_long_header_packet(REJ, 0x00, QUIC_VERSION, client_cid, server_cid, 1, [rej_frame])
    packet_size = len(rej_packet)
    sent_rej = server_socket.sendto(rej_packet, address)
    if sent_rej != len(rej_packet):
        return False
    print("Sent the message 'REJ' to the client")
    return packet_size

# Function to receive the complete message 'ClientHello' from the client
def receive_complete_chlo(server_socket):
    data, address = server_socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the client.")
        return False
    long_packet_type, version, dest_cid, source_cid, packet_number, frames = parse_long_header_packet(data)
    if long_packet_type != INITIAL_COMPLETE:
        print("Error: Expected 'CHLO' packet from the client")
        return False
    print("Received the complete message 'CHLO' from the client")
    # Extract the client's public key and times from the frames
    client_public_key = frames[0][3]
    times = struct.unpack('!I', frames[0][3][-4:])[0] # times in the last 4 bytes
    return client_public_key, times

# Function to send the message 'SHLO' to the client
def send_shlo(server_socket, address, server_cid, client_cid, server_public_key):
    shlo_frame = build_frame(SHLO, 0, 0, server_public_key)
    shlo_packet = build_long_header_packet(HANDSHAKE_DONE, 0x00, QUIC_VERSION, client_cid, server_cid, 2, [shlo_frame])
    packet_size = len(shlo_packet)
    sent_shlo = server_socket.sendto(shlo_packet, address)
    if sent_shlo != len(shlo_packet):
        return False
    print("Sent the message 'SHLO' to the client")
    return packet_size

# Function to send file
def send_file(client_socket, server_address, dest_cid, file_path, packet_list, symmetric_key_flag):
    packet_number = 3 # starting packet number
    chunk_size = 1000 # 1 KB
    if symmetric_key_flag is False:
        print("Error: Symmetric key not established")
        return False
    try:
        # Open the file and read the data
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(chunk_size)
                if not data:
                    break # End of file
                # Send the data to the server
                sent_data = send_data(client_socket, server_address, packet_number, data, dest_cid)
                if not sent_data:
                    print("Error sending the file to the server")
                    return False
                sent_data_time = time.time()
                ack_received = receive_ack(client_socket)
                if ack_received != packet_number:
                    print(f"Error: Expected ACK for packet {packet_number}")
                    return False
                receive_ack_time = time.time()
                packet_list.insert(packet_number, receive_ack_time, sent_data_time, sent_data) # Insert the packet send and ACK receive times
                packet_number += 1

    except FileNotFoundError:
        print("Error: File not found")
        return False
    print("File sent successfully to the server")
    return packet_number

# Function to receive file and save it to the output file path
def receive_file(server_socket, output_file_path, client_address):
    chunk_size = 1000  # 1 KB
    # file size is 2 * 1024 * 1024
    expected_packets = (2 * 1024 * 1024 + chunk_size - 1) // chunk_size # Calculate the expected number of packets
    received_packets = 0
    try:
        # Open the file and write the data
        with open(output_file_path, 'wb') as file:
            while True:
                frames, dest_cid, packet_number = receive_data(server_socket)
                if not frames:
                    print("Error receiving data from the client")
                    return False

                for frame in frames:
                    _, _, _, data = frame
                    file.write(data)

                ack_sent = send_ack(server_socket, client_address, dest_cid, packet_number)
                if not ack_sent:
                    print("Error sending ACK to the client")
                    return False

                received_packets += 1
                if received_packets == expected_packets:
                    break

    except FileNotFoundError:
        print("Error: File not found")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

    return True

# Function to send close message to the server
def send_close(client_socket, server_address, dest_cid, packet_number):
    close_frame = build_frame(CLOSE, 0, 0, b'')  # Close frame
    short_packet = build_short_header_packet(dest_cid, packet_number, [close_frame], 0, 0)
    packet_size = len(short_packet)
    sent_close = client_socket.sendto(short_packet, server_address)
    if sent_close != len(short_packet):
        return False
    print("Sent the close packet to the server")
    return packet_size

# Function to receive close message from the server
def receive_close(server_socket):
    data, _ = server_socket.recvfrom(BUFFER_SIZE)
    if not data:
        print("Error: No data received from the server.")
        return False
    _, _, _, _, _, packet_number, frames = parse_short_header_packet(data)
    if frames[0][0] != CLOSE:
        print("Error: Expected CLOSE frame from the server")
        return False
    print("Received the close packet from the server")
    return packet_number

# Function to simulate network conditions
def simulate_network_conditions(packet_list, delays):
    packet_number = 1
    packet_size = 1000  # 1 KB
    for delay in delays:
        send_time = time.time()
        time.sleep(delay)  # Simulate network delay
        ack_time = time.time()
        packet_list.insert(packet_number, ack_time, send_time, packet_size)
        packet_number += 1























































