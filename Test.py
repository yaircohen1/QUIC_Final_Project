import threading
import unittest
from socket import *
from Client import *
from Server import *
from Quic_Api import *
from LinkedList import *

def create_server_socket(server_address):
    """Create and bind a server socket."""
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    try:
        server_socket.bind(server_address)
        print(f"Server bound to {server_address}")
    except Exception as e:
        print(f"Error binding server socket: {e}")
        server_socket.close()
        return None
    return server_socket

def create_client_socket():
    """Create a client socket."""
    return socket(AF_INET, SOCK_DGRAM)

def simulate_quic_interaction(server_address):
    """Sets up and runs a QUIC server in a separate thread, returning server controls."""
    stop_event = threading.Event()

    server_socket = create_server_socket(server_address)
    if not server_socket:
        return None, None, None

    server_thread = threading.Thread(target=run_server, args=(server_socket, stop_event))
    server_thread.start()

    return server_socket, stop_event, server_thread

def run_server(server_socket, stop_event):
    """Simulate a simple QUIC server."""
    try:
        while not stop_event.is_set():
            pass
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()
        print("Server socket closed.")

class TestClient(unittest.TestCase):

    def test_generate_random_data(self):
        size = 1024  # 1 KB
        data = generate_random_data(size)
        self.assertEqual(len(data), size)  # Check if data is of correct size

    def test_parse_arguments(self):
        argv = ["Client.py", "-ip", "127.0.0.1", "-p", "8080", "-t", "3"]
        ip_address, port, times = parse_arguments(argv)
        self.assertEqual(ip_address, "127.0.0.1")
        self.assertEqual(port, 8080)

class TestServer(unittest.TestCase):

    def test_parse_server_arguments(self):
        argv = ["Server.py", "-p", "8080"]
        port = parse_server_arguments(argv)
        self.assertEqual(port, 8080)

class TestQUICApi(unittest.TestCase):

    def test_encrypt_decrypt(self):
        data = b'This is a test message.'
        nonce = os.urandom(12)  # 12 bytes for GCM nonce
        key = os.urandom(32)  # 32 bytes for AES-256 key

        # Encrypt the data
        ciphertext, tag = encrypt(data, nonce, key)

        # decrypt the ciphertext
        decrypted_data = decrypt(nonce, ciphertext, tag, key)

        self.assertEqual(decrypted_data, data)

        # Assert that the ciphertext and tag are returned and have the expected length
        self.assertEqual(len(tag), 16)  # GCM tag is always 16 bytes
        self.assertNotEqual(ciphertext, data)  # Ciphertext should not equal the original data

    def test_generate_cid(self):
        cid = generate_cid()

        # Assert that the CID is 8 bytes long
        self.assertEqual(len(cid), 8)

        # Assert that the CID is not equal to another CID generated immediately after
        another_cid = generate_cid()
        self.assertNotEqual(cid, another_cid)

    def test_build_and_parse_frame(self):
        """Test build_frame and parse_frame functions."""
        frame_type = 0x01
        stream_id = 1234
        offset = 5678
        data = b'Test data payload'

        # Build the frame
        frame = build_frame(frame_type, stream_id, offset, data)

        # Parse the frame
        parsed_frame_type, parsed_stream_id, parsed_offset, parsed_data = parse_frame(frame)

        # Assertions
        self.assertEqual(parsed_frame_type, frame_type)
        self.assertEqual(parsed_stream_id, stream_id)
        self.assertEqual(parsed_offset, offset)
        self.assertEqual(parsed_data, data)

    def test_build_and_parse_long_short_header_packet(self):
        """Test build_long_header_packet, parse_long_header_packet, build_short_header_packet, and parse_short_header_packet together."""
        # Long Header Packet
        packet_type = 0x80  # Example packet type (long header)
        type_specific_bits = 0x00
        version = 1
        dest_cid = os.urandom(8)  # Random 8-byte connection ID
        source_cid = os.urandom(8)  # Random 8-byte connection ID
        packet_number = 12345

        # Construct valid frames using build_frame
        frame1 = build_frame(0x01, 1234, 0, b'Test data 1')
        frame2 = build_frame(0x01, 5678, 0, b'Test data 2')
        frames = [frame1, frame2]

        long_header_packet = build_long_header_packet(packet_type, type_specific_bits, version, dest_cid, source_cid,
                                                      packet_number, frames)

        # Parse Long Header Packet
        long_packet_type, parsed_version, parsed_dest_cid, parsed_source_cid, parsed_packet_number, parsed_frames = parse_long_header_packet(
            long_header_packet)

        # Extract just the data portions of the parsed frames
        parsed_data_list = [data for _, _, _, data in parsed_frames]

        # Extract the data portions of the original frames
        original_data_list = [parse_frame(frame)[3] for frame in frames]

        # Assertions for Long Header Packet
        self.assertEqual(long_packet_type, packet_type & 0x3)
        self.assertEqual(parsed_version, version)
        self.assertEqual(parsed_dest_cid[:len(dest_cid)], dest_cid)  # Compare only the original length
        self.assertEqual(parsed_source_cid[:len(source_cid)], source_cid)  # Compare only the original length
        self.assertEqual(parsed_packet_number, packet_number)
        self.assertEqual(parsed_data_list, original_data_list)

        # Short Header Packet
        short_header_packet = build_short_header_packet(dest_cid, packet_number, frames, key_phase=0, spin_bit=0)

        # Parse Short Header Packet
        header_form, fixed_bit, spin_bit, key_phase, parsed_dest_cid, parsed_packet_number, parsed_frames = parse_short_header_packet(
            short_header_packet)

        # Extract just the data portions of the parsed frames
        parsed_data_list = [data for _, _, _, data in parsed_frames]

        # Assertions for Short Header Packet
        self.assertEqual(header_form, 0)  # Ensure the header form indicates short header
        self.assertEqual(parsed_dest_cid[:len(dest_cid)], dest_cid)  # Compare only the original length
        self.assertEqual(parsed_packet_number, packet_number)
        self.assertEqual(parsed_data_list, original_data_list)

    def test_send_and_receive_first_chlo(self):
        """Test the send_first_chlo and receive_first_chlo functions."""
        server_address = ('127.0.0.1', 8081)
        client_cid = b'\x01\x02\x03\x04'

        server_socket, stop_event, server_thread = simulate_quic_interaction(server_address)
        if not server_socket:
            self.fail("Server setup failed, could not bind to the address.")

        try:
            client_socket = create_client_socket()
            packet_size = send_first_chlo(client_socket, server_address, client_cid)

            self.assertGreater(packet_size, 0, "No data was sent by the client.")

            received_cid, client_address = receive_first_chlo(server_socket)
            self.assertEqual(received_cid, client_cid, "The server did not receive the correct CHLO packet.")
        finally:
            client_socket.close()
            stop_event.set()
            server_thread.join()
            server_socket.close()

    def test_send_and_receive_complete_chlo(self):
        """Test the send_complete_chlo and receive_complete_chlo functions."""
        server_address = ('127.0.0.1', 8081)
        client_cid = b'\x01\x02\x03\x04'
        server_cid = b'\x05\x06\x07\x08'
        client_public_key = b'client_public_key'
        times = 3

        server_socket, stop_event, server_thread = simulate_quic_interaction(server_address)
        if not server_socket:
            self.fail("Server setup failed, could not bind to the address.")

        try:
            client_socket = create_client_socket()
            packet_size = send_complete_chlo(client_socket, server_address, client_cid, server_cid, client_public_key, times)

            self.assertGreater(packet_size, 0, "No data was sent by the client for complete CHLO.")

            received_public_key, received_times = receive_complete_chlo(server_socket)

            self.assertEqual(received_public_key[:len(client_public_key)], client_public_key,
                             "The server did not receive the correct public key in the complete CHLO packet.")
            self.assertEqual(received_times, times,
                             "The server did not receive the correct times in the complete CHLO packet.")
        finally:
            client_socket.close()
            stop_event.set()
            server_thread.join()
            server_socket.close()

    def test_send_receive_ack(self):
        """Test send_ack and receive_ack functions together"""
        dest_cid = generate_cid()
        server_address = ('127.0.0.1', 8081)

        server_socket, stop_event, server_thread = simulate_quic_interaction(server_address)
        if not server_socket:
            self.fail("Server setup failed, could not bind to the address.")

        try:
            client_socket = create_client_socket()
            packet_number = 1
            send_ack(client_socket, server_address, dest_cid, packet_number)
            print("Client sent ACK to the server.")

            # Simulate server behavior for receiving ACK
            def server_behavior():
                try:
                    while True:
                        data, _ = server_socket.recvfrom(BUFFER_SIZE)
                        if not data:
                            break
                        header_form, _, _, _, _, received_packet_number, frames = parse_short_header_packet(data)
                        if frames[0][0] == ACK and received_packet_number == packet_number:
                            print("Server received the correct ACK.")
                            return True
                        else:
                            print("Server received incorrect ACK.")
                            return False
                except Exception as e:
                    print(f"Server error: {e}")
                    return False

            server_result = server_behavior()
            self.assertTrue(server_result, "The server did not receive the ACK correctly.")
        finally:
            client_socket.close()
            stop_event.set()
            server_thread.join()
            server_socket.close()

    def test_send_receive_data(self):
        """Test send_data and receive_data functions together"""
        dest_cid = generate_cid()
        server_address = ('127.0.0.1', 8082)

        server_socket, stop_event, server_thread = simulate_quic_interaction(server_address)
        if not server_socket:
            self.fail("Server setup failed, could not bind to the address.")

        try:
            client_socket = create_client_socket()
            client_socket.sendto(b'Client ready to receive data', server_address)
            print("Client notified server it is ready to receive data.")

            client_address = None
            try:
                data, client_address = server_socket.recvfrom(1024)
                print(f"Server received readiness message from client at {client_address}")
            except Exception as e:
                print(f"Error receiving client's readiness message: {e}")
                self.fail("Server failed to receive the client's readiness message.")

            if client_address:
                data_to_send = b'This is test data.'
                packet_number = 1
                send_data(server_socket, client_address, packet_number, data_to_send, dest_cid)
                print("Server sent data to the client.")

                frames, received_dest_cid, received_packet_number = receive_data(client_socket)
                print(f"Client received data frames.")

                # Reconstruct the full data from the frames received
                received_data = b''.join([frame[3] for frame in frames])

                self.assertEqual(received_packet_number, packet_number,
                                 "The client did not receive the correct packet number.")
                self.assertEqual(received_data, data_to_send, "The client did not receive the correct data.")
        finally:
            client_socket.close()
            stop_event.set()
            server_thread.join()
            server_socket.close()

    def test_send_and_receive_rej(self):
        """Test send_rej and receive_rej functions"""
        server_address = ('127.0.0.1', 8083)
        client_cid = b'\x01\x02\x03\x04'
        server_cid = b'\x05\x06\x07\x08'

        server_socket, stop_event, server_thread = simulate_quic_interaction(server_address)
        if not server_socket:
            self.fail("Server setup failed, could not bind to the address.")

        try:
            client_socket = create_client_socket()
            client_socket.sendto(b'Client Hello', server_address)
            print("Client sent 'Client Hello' to the server.")

            client_address = None
            try:
                data, client_address = server_socket.recvfrom(1024)
                print(f"Server received: {data} from {client_address}")
            except Exception as e:
                print(f"Error receiving client's message: {e}")
                self.fail("Server failed to receive the client's message.")

            if client_address:
                send_rej(server_socket, client_address, server_cid, client_cid)
                print("Server sent REJ packet to the client.")

                received_server_cid = receive_rej(client_socket)
                print(f"Client received REJ packet with CID: {received_server_cid}")

                self.assertIsNotNone(received_server_cid, "Failed to receive server CID.")
        finally:
            client_socket.close()
            stop_event.set()
            server_thread.join()
            server_socket.close()

    def test_send_close(self):
        """Test send_close function"""
        server_address = ('127.0.0.1', 8087)
        dest_cid = generate_cid()
        packet_number = 1

        server_socket, stop_event, server_thread = simulate_quic_interaction(server_address)
        if not server_socket:
            self.fail("Server setup failed, could not bind to the address.")

        try:
            client_socket = create_client_socket()
            packet_size = send_close(client_socket, server_address, dest_cid, packet_number)
            print("Client sent close packet to the server.")

            client_address = None
            try:
                data, client_address = server_socket.recvfrom(1024)
                print(f"Server received close packet from client at {client_address}")
            except Exception as e:
                print(f"Error receiving close packet: {e}")
                self.fail("Server failed to receive the close packet.")

            self.assertGreater(packet_size, 0, "Client failed to send a close packet.")
            self.assertIsNotNone(client_address, "Server failed to receive the client's address.")
        finally:
            client_socket.close()
            stop_event.set()
            server_thread.join()
            server_socket.close()

    def test_simulate_network_conditions(self):
        """Test simulate_network_conditions function"""
        packet_list = PacketList()
        delays = [0.05, 0.1, 0.2]

        simulate_network_conditions(packet_list, delays)

        self.assertEqual(packet_list.size, len(delays))

class TestLinkedList(unittest.TestCase):

    def test_insert(self):
        packet_list = PacketList()

        packet_number = 1
        ack_receive_time = time.time()
        packet_send_time = ack_receive_time - 0.1  # RTT of 0.1 seconds
        packet_size = 1000

        packet_list.insert(packet_number, ack_receive_time, packet_send_time, packet_size)

        self.assertEqual(packet_list.size, 1)
        self.assertEqual(packet_list.head.packet_number, packet_number)
        self.assertAlmostEqual(packet_list.head.sample_rtt, 0.1, places=6)
        self.assertEqual(packet_list.head.packet_size, packet_size)

    def test_min_smoothed_rtt_and_variance(self):
        packet_list = PacketList()

        packet_list.insert(1, time.time(), time.time() - 0.1, 1000)
        packet_list.insert(2, time.time(), time.time() - 0.05, 1000)

        packet_list.calculate_min_rtt()
        self.assertAlmostEqual(packet_list.head.next.rtt_min, 0.05, places=6)

        node = packet_list.head.next
        self.assertAlmostEqual(node.rtt_smooth, (1 - ALPHA) * packet_list.head.rtt_smooth + ALPHA * node.sample_rtt, places=6)
        self.assertAlmostEqual(node.rtt_var, (1 - BETA) * packet_list.head.rtt_var + BETA * abs(node.rtt_smooth - node.sample_rtt), places=6)

    def test_packet_lost(self):
        packet_list = PacketList()

        node_not_lost = Node(1, 0.2, 0.1, 100)
        self.assertFalse(packet_list.packet_lost(node_not_lost))

        node_lost_rtt = Node(2, 0.5, 0.1, 100)
        node_lost_rtt.rtt_smooth = 0.1
        node_lost_rtt.rtt_var = 0.05
        self.assertTrue(packet_list.packet_lost(node_lost_rtt))

        node_lost_flag = Node(3, 0.2, 0.1, 100, experiment_lost_flag=True)
        self.assertTrue(packet_list.packet_lost(node_lost_flag))

    def test_packet_acknowledged(self):
        packet_list = PacketList()

        node = Node(1, 0.2, 0.1, 100)
        node.rtt_smooth = 0.3
        self.assertTrue(packet_list.packet_acknowledged(node))

        node.rtt_smooth = 0.1
        self.assertFalse(packet_list.packet_acknowledged(node))

    def test_persistent_congestion_detected(self):
        packet_list = PacketList()

        packet_list.insert(1, 0.1, 0.0, 1)

        node = Node(packet_number=2, ack_receive_time=1.0, packet_send_time=0.0, packet_size=1)

        node.rtt_smooth = 0.1
        node.rtt_var = 0.01

        node.sample_rtt = 1.0

        self.assertTrue(packet_list.persistent_congestion_detected(node), "Persistent congestion should be detected")

    def test_simulate_packet_transmission(self):
        packet_list = PacketList()

        delays = [0.1, 0.2, 0.3]
        losses = [1]

        packet_numbers, cwnd_values, states = packet_list.simulate_packet_transmission(delays, losses)

        self.assertEqual(len(packet_numbers), 3)
        self.assertEqual(len(cwnd_values), 3)
        self.assertEqual(len(states), 3)

        self.assertTrue(packet_list.head.next.experiment_lost_flag)

        self.assertIn('Recovery', states)

if __name__ == '__main__':
    unittest.main()
