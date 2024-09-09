import pyshark
import sqlite3
from tabulate import tabulate

## loads the pcap file and returns the capture object
def load_pcap(file_path):
    try:
        print(f"Loading PCAP file: {file_path}")
        capture = pyshark.FileCapture(file_path)
        for packet in capture:
            print("PCAP file loaded successfully.")
            return capture
        print("No packets found in the PCAP file.")
        return None
    except Exception as e:
        print(f"Error loading PCAP file: {e}")
        return None

## processes basic information like ip addresses and packet length
def process_basic_info(capture):
    print("Processing basic packet information...")
    basic_info = []
    for packet in capture:
        if 'IP' in packet:
            basic_info.append({
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'protocol': packet.transport_layer,
                'length': packet.length,
                'timestamp': packet.sniff_timestamp
            })
    print("Basic packet information processed.")
    return basic_info

## analyzes protocol distribution and counts occurrences
def process_protocol_distribution(capture):
    print("Processing protocol distribution...")
    protocols = {}
    for packet in capture:
        if hasattr(packet, 'highest_layer'):
            protocol = packet.highest_layer
            protocols[protocol] = protocols.get(protocol, 0) + 1
    print("Protocol distribution processed.")
    return protocols

## identifies the most active ip addresses (top talkers)
def process_top_talkers(capture):
    print("Processing top talkers...")
    ip_counts = {}
    for packet in capture:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
            ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
    top_talkers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    print("Top talkers processed.")
    return top_talkers

## creates or connects to the sqlite database and creates tables
def create_database():
    print("Creating/connecting to SQLite database...")
    conn = sqlite3.connect('pcap_analysis.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS basic_info
                 (src_ip TEXT, dst_ip TEXT, protocol TEXT, length INTEGER, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS protocol_distribution
                 (protocol TEXT, count INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS top_talkers
                 (ip_address TEXT, packet_count INTEGER)''')
    conn.commit()
    print("Database ready.")
    return conn

## stores the processed results in the respective tables
def store_results(conn, data, table_name):
    print(f"Storing results in {table_name} table...")
    c = conn.cursor()
    if table_name == 'basic_info':
        c.executemany('INSERT INTO basic_info VALUES (?,?,?,?,?)', 
                      [(d['src_ip'], d['dst_ip'], d['protocol'], d['length'], d['timestamp']) for d in data])
    elif table_name == 'protocol_distribution':
        c.executemany('INSERT INTO protocol_distribution VALUES (?,?)', data.items())
    elif table_name == 'top_talkers':
        c.executemany('INSERT INTO top_talkers VALUES (?,?)', data)
    conn.commit()
    print(f"Results stored in {table_name} table.")

## displays the results stored in the database as tables
def display_results(conn):
    while True:
        print("\nSelect a table to display:")
        print("1. Basic Info")
        print("2. Protocol Distribution")
        print("3. Top Talkers")
        print("4. Return to main menu")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            table_name = 'basic_info'
        elif choice == '2':
            table_name = 'protocol_distribution'
        elif choice == '3':
            table_name = 'top_talkers'
        elif choice == '4':
            return
        else:
            print("Invalid choice. Please try again.")
            continue
        
        c = conn.cursor()
        c.execute(f'SELECT * FROM {table_name}')
        rows = c.fetchall()
        headers = [description[0] for description in c.description]
        print(tabulate(rows, headers=headers, tablefmt='grid'))

## closes the capture object to free up resources
def close_capture(capture):
    """Close the capture object to clean up resources."""
    if capture:
        try:
            print("Closing capture object...")
            capture.close()
        except Exception as e:
            print(f"Error closing capture: {e}")

## main menu for the user to interact with the program
def main_menu():
    capture = None
    conn = create_database()
    
    while True:
        print("\n===== PCAP Analysis Program =====")
        print("1. Load PCAP file")
        print("2. Process basic packet info")
        print("3. Process protocol distribution")
        print("4. Process top talkers")
        print("5. Display results")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ")
        
        if choice == '1':
            file_path = input("Enter the path to the PCAP file: ")
            if capture:
                close_capture(capture)  # Close the previous capture if any
            capture = load_pcap(file_path)
        elif choice in ['2', '3', '4']:
            if capture is not None:
                if choice == '2':
                    data = process_basic_info(capture)
                    store_results(conn, data, 'basic_info')
                elif choice == '3':
                    data = process_protocol_distribution(capture)
                    store_results(conn, data, 'protocol_distribution')
                elif choice == '4':
                    data = process_top_talkers(capture)
                    store_results(conn, data, 'top_talkers')
            else:
                print("Please load a valid PCAP file first.")
        elif choice == '5':
            display_results(conn)
        elif choice == '6':
            print("Exiting program. Goodbye!")
            close_capture(capture) ##close the capture when exiting the program
            break
        else:
            print("Invalid choice. Please try again.")
    
    conn.close()

if __name__ == "__main__":
    main_menu()
