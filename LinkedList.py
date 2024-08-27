import matplotlib.pyplot as plt
import time
import math

# Global variables for congestion control
cwnd = 1 # Congestion Window Size (representing the number of packets that can be sent before receiving an ACK)
ssthresh = 8
state = 'Slow Start' # State of the congestion control algorithm (initially set to Slow Start)
persistent_congestion_duration = None  # To track persistent congestion duration
last_acknowledged_packet = -1  # Last acknowledged packet number
duplicate_ack_count = 0  # Count of duplicate ACKs received

# CONSTANTS
ALPHA = 0.125
BETA = 0.25
MIN_CWND = 1
PERSISTENT_CONGESTION_MULTIPLIER = 3  # Multiplier for persistent congestion detection

class Node:
    def __init__(self, packet_number, ack_receive_time, packet_send_time, packet_size, experiment_lost_flag = False):
        self.packet_number = packet_number
        self.ack_receive_time = ack_receive_time
        self.packet_send_time = packet_send_time
        self.sample_rtt = ack_receive_time - packet_send_time
        self.packet_size = packet_size
        self.experiment_lost_flag = experiment_lost_flag
        self.rtt_min = self.sample_rtt
        self.rtt_smooth = self.sample_rtt
        self.rtt_var = self.sample_rtt / 2
        self.next = None

class PacketList:
    def __init__(self):
        self.head = None
        self.size = 0

    # Insert last node
    def insert(self, packet_number, ack_receive_time, packet_send_time, packet_size, experiment_lost_flag = False):
        new_node = Node(packet_number, ack_receive_time, packet_send_time, packet_size, experiment_lost_flag)
        if self.head is None:
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node
        self.size += 1

        # Update the RTT values
        self.calculate_smoothed_rtt(new_node)
        self.calculate_rtt_variance(new_node)

        # Run the New Reno Congestion Control Algorithm
        self.new_reno_congestion_control(new_node)


    # Calculate the minimum RTT
    def calculate_min_rtt(self):
        current = self.head
        while current:
            if current.sample_rtt < current.rtt_min:
                current.rtt_min = current.sample_rtt
            current = current.next

    # Calculate the smoothed RTT
    def calculate_smoothed_rtt(self, node):
        if node != self.head:
            prev_node = self.head
            while prev_node.next != node:
                prev_node = prev_node.next
            node.rtt_smooth = (1 - ALPHA) * prev_node.rtt_smooth + ALPHA * node.sample_rtt

    # Calculate the RTT variance
    def calculate_rtt_variance(self, node):
        if node != self.head:
            prev_node = self.head
            while prev_node.next != node:
                prev_node = prev_node.next
            node.rtt_var = (1 - BETA) * prev_node.rtt_var + BETA * abs(node.rtt_smooth - node.sample_rtt)


    # Print the RTT values
    def print_rtt_values(self):
        current = self.head
        while current:
            print(f"Sample RTT: {current.sample_rtt}, Smoothed RTT: {current.rtt_smooth}, RTT Variance: {current.rtt_var}")
            current = current.next

    # Create a graph for sample_RTT and smoothed_RTT
    def create_graph(self, title):
        sample_rtt = []
        smoothed_rtt = []
        current = self.head
        while current:
            sample_rtt.append(current.sample_rtt)
            smoothed_rtt.append(current.rtt_smooth)
            current = current.next
        #give the graph a title
        plt.title(title)
        plt.plot(sample_rtt, label='Sample RTT')
        plt.plot(smoothed_rtt, label='Smoothed RTT')
        plt.xlabel('time (seconds)')
        plt.ylabel('RTT (milliseconds)')
        plt.legend()
        plt.show()

    # New Reno Congestion Control Algorithm
    def new_reno_congestion_control(self, node):
        global cwnd, ssthresh, state

        print(f"State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

        if state == 'Slow Start':
            cwnd += node.packet_size  # Increase cwnd based on the number of acknowledged bytes (packet_size)
            if cwnd >= ssthresh:
                state = 'Congestion Avoidance'
                print(f"Exiting Slow Start, entering Congestion Avoidance: State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

            if self.packet_lost(node):
                ssthresh = max(cwnd / 2, 2 * node.packet_size)
                cwnd = ssthresh
                state = 'Recovery'
                print(f"Packet lost, entering Recovery: State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

        elif state == 'Recovery':
            cwnd = max(cwnd / 2, MIN_CWND * node.packet_size)
            ssthresh = cwnd
            if self.packet_acknowledged(node):
                state = 'Congestion Avoidance'
                print(
                    f"Exiting Recovery, entering Congestion Avoidance: State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

        elif state == 'Congestion Avoidance':
            cwnd += node.packet_size / cwnd  # AIMD approach
            if self.packet_lost(node):
                ssthresh = max(cwnd / 2, MIN_CWND * node.packet_size)
                cwnd = ssthresh
                state = 'Recovery'
                print(f"Packet lost, entering Recovery: State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

        if self.persistent_congestion_detected(node):
            cwnd = MIN_CWND * node.packet_size
            state = 'Slow Start'
            print(
                f"Persistent congestion detected, re-entering Slow Start: State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

        print(f"After update: State: {state}, cwnd: {cwnd}, ssthresh: {ssthresh}")

    def packet_lost(self, node):
        if node.sample_rtt > node.rtt_smooth + 4 * node.rtt_var or node.experiment_lost_flag:
            return True

    def packet_acknowledged(self, node):
        return node.sample_rtt < node.rtt_smooth

    def persistent_congestion_detected(self, node):
        global persistent_congestion_duration
        if persistent_congestion_duration is None:
            persistent_congestion_duration = PERSISTENT_CONGESTION_MULTIPLIER * (node.rtt_smooth + 4 * node.rtt_var)

        return node.sample_rtt > persistent_congestion_duration

    def simulate_packet_transmission(self, delays, losses):
        global state, cwnd, ssthresh

        packet_number = 0
        packet_numbers = []
        cwnd_values = []
        states = []

        for delay in delays:
            send_time = time.time()
            time.sleep(delay)

            # Determine if this packet should be lost based on the experimental setup
            experiment_lost_flag = packet_number in losses

            ack_time = time.time()
            packet_size = 1  # Set packet size as a constant for simplicity, or modify as needed
            self.insert(packet_number, ack_time, send_time, packet_size, experiment_lost_flag)

            packet_numbers.append(packet_number)
            cwnd_values.append(cwnd)
            states.append(state)

            packet_number += 1

        return packet_numbers, cwnd_values, states

# Experiment
def main():
    # Define delays for packet transmission in seconds
    delays = [0.05, 0.1, 0.05, 0.4, 0.05, 0.2, 0.3, 0.1, 0.05, 0.4, 0.1, 0.2]

    # Define which packet numbers should be considered lost (for experimental purposes)
    losses = [3, 7]  # Packet numbers that will be marked as lost

    client_packet_list = PacketList()
    packet_numbers, cwnd_values, states = client_packet_list.simulate_packet_transmission(delays, losses)

    # Plotting the results
    plt.figure(figsize=(10, 6))

    # Plot the congestion window size and algorithm state
    plt.subplot(2, 1, 1)
    plt.plot(packet_numbers, cwnd_values, label='cwnd', color='blue')
    plt.scatter(packet_numbers, [1 if s == 'Slow Start' else 2 if s == 'Congestion Avoidance' else 3 for s in states],
                color='red', label='State (1=SS, 2=CA, 3=Recovery)', marker='x')
    plt.xlabel('Packet Number')
    plt.ylabel('Congestion Window / State')
    plt.legend()

    # Plot the RTT values
    plt.subplot(2, 1, 2)
    sample_rtt, smoothed_rtt = [], []
    current = client_packet_list.head
    while current:
        sample_rtt.append(current.sample_rtt)
        smoothed_rtt.append(current.rtt_smooth)
        current = current.next
    plt.plot(packet_numbers, sample_rtt[:len(packet_numbers)], label='Sample RTT')
    plt.plot(packet_numbers, smoothed_rtt[:len(packet_numbers)], label='Smoothed RTT')
    plt.xlabel('Packet Number')
    plt.ylabel('RTT (seconds)')
    plt.legend()

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()







