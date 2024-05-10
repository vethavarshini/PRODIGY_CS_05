import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, TCP, IP, Ether, Raw
import threading
import tkinter.messagebox as messagebox
import datetime

# Global variable to store packet list and count
packet_list = []
packet_count = 0
sniffer = None
sniffing = False
hover_popup = None  # Global variable to store hover popup


def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Append packet to the list
    packet_list.append(packet)

    # Display the packet in the Treeview
    display_packet(packet_count, packet)


def display_packet(packet_num, packet):
    # Extract relevant information from the packet
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_mac = packet[Ether].src if Ether in packet else "-"
    dst_mac = packet[Ether].dst if Ether in packet else "-"
    src_ip = packet[IP].src if IP in packet else "-"
    dst_ip = packet[IP].dst if IP in packet else "-"
    src_port = packet[TCP].sport if TCP in packet else "-"
    dst_port = packet[TCP].dport if TCP in packet else "-"
    protocol = packet[IP].proto if IP in packet else "-"
    payload_len = len(packet[Raw].load) if Raw in packet else 0

    # Insert packet information into the Treeview
    tree.insert("", "end", values=(
        packet_num, timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, payload_len))


def show_packet_info(event):
    # Get the item selected in the Treeview
    item = tree.selection()[0]
    packet_info = tree.item(item, "values")

    # Display packet information in a message box
    messagebox.showinfo("Packet Information", f"Packet Number: {packet_info[0]}\n"
                                               f"Timestamp: {packet_info[1]}\n"
                                               f"Source MAC: {packet_info[2]}\n"
                                               f"Destination MAC: {packet_info[3]}\n"
                                               f"Source IP: {packet_info[4]}\n"
                                               f"Destination IP: {packet_info[5]}\n"
                                               f"Source Port: {packet_info[6]}\n"
                                               f"Destination Port: {packet_info[7]}\n"
                                               f"Protocol: {packet_info[8]}\n"
                                               f"Payload Length: {packet_info[9]}")


def start_sniffing():
    global sniffer, sniffing
    if not sniffing:
        sniffing = True
        # Start capturing packets using scapy sniff function
        # Adjust the 'iface' parameter to your network interface (e.g., 'eth0' for Ethernet)
        sniffer = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False))
        sniffer.start()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)


def stop_sniffing():
    global sniffer, sniffing
    if sniffing:
        sniffing = False
        if sniffer and sniffer.is_alive():
            sniffer.join()
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)


# Create a Tkinter window
root = tk.Tk()
root.title("Network Packet Analyzer")

# Increase font size for all elements
root.option_add("*Font", "Helvetica 12")

# Create a Frame for start and stop sniffing buttons
button_frame = ttk.Frame(root)
button_frame.pack(pady=10)

# Start button
start_button = ttk.Button(button_frame, text="Start Sniffing", command=start_sniffing, style="Start.TButton")
start_button.grid(row=0, column=0, padx=5)

# Stop button
stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED,
                         style="Stop.TButton")
stop_button.grid(row=0, column=1, padx=5)

# Create a custom style for buttons
style = ttk.Style()
style.configure("Start.TButton", foreground="white", background="green")
style.map("Start.TButton", background=[("active", "darkgreen")])
style.configure("Stop.TButton", foreground="white", background="red")
style.map("Stop.TButton", background=[("active", "darkred")])

# Create a Treeview widget to display packet information in a tabular format
tree = ttk.Treeview(root, columns=(
    "Packet Number", "Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Source Port",
    "Destination Port", "Protocol", "Payload Length"))
tree.heading("#0", text="", anchor=tk.CENTER)
tree.heading("Packet Number", text="Packet Number", anchor=tk.CENTER)
tree.heading("Timestamp", text="Timestamp", anchor=tk.CENTER)
tree.heading("Source MAC", text="Source MAC", anchor=tk.CENTER)
tree.heading("Destination MAC", text="Destination MAC", anchor=tk.CENTER)
tree.heading("Source IP", text="Source IP", anchor=tk.CENTER)
tree.heading("Destination IP", text="Destination IP", anchor=tk.CENTER)
tree.heading("Source Port", text="Source Port", anchor=tk.CENTER)
tree.heading("Destination Port", text="Destination Port", anchor=tk.CENTER)
tree.heading("Protocol", text="Protocol", anchor=tk.CENTER)
tree.heading("Payload Length", text="Payload Length", anchor=tk.CENTER)
tree.pack(fill=tk.BOTH, expand=True)

# Start the Tkinter event loop
root.mainloop()

