import random
import time
from scapy.all import *

# Target IP (set your IDS destination IP)
TARGET_IP = "192.168.100.21"

# Interface to send packets on
INTERFACE = "Intel(R) Dual Band Wireless-AC 7260"

# KDD99-based attack features (for reference/logging)
attack_signatures = {
    'DoS': {
        'protocol': 'icmp',
        'service': 'ecr_i',
        'payload_size': 1024,
        'count': 511,
        'serror_rate': 1.0,
        'same_srv_rate': 1.0
    },
    'Probe': {
        'protocol': 'tcp',
        'service': 'ftp',
        'flag': 'S',
        'dport': 21,
        'src_bytes': 42,
        'dst_bytes': 0,
        'count': 30,
        'rerror_rate': 0.7,
        'same_srv_rate': 0.6
    },
    'R2L': {
        'protocol': 'tcp',
        'service': 'ftp',
        'flag': 'R',
        'dport': 21,
        'payload': "USER root\r\nPASS guess\r\n",
        'num_failed_logins': 3,
        'rerror_rate': 1.0
    },
    'U2R': {
        'protocol': 'tcp',
        'service': 'telnet',
        'flag': 'P',
        'dport': 23,
        'payload': "exploit_root_shell();",
        'num_root': 2,
        'num_file_creations': 3
    }
}

def send_attack_loop(attack_type):
    sig = attack_signatures[attack_type]
    print(f"\n[*] Sending {attack_type} packets to {TARGET_IP} on '{INTERFACE}' — Ctrl+C to stop.")

    try:
        while True:
            sport = random.randint(1024, 65535)

            if sig['protocol'] == 'icmp':
                # ICMP DoS-style burst with payload
                pkt = IP(dst=TARGET_IP)/ICMP(type=8)/Raw(load="X"*sig['payload_size'])

            elif sig['protocol'] == 'tcp':
                # Use default dport or fall back to common ones
                dport = sig.get('dport', 80)
                flags = sig.get('flag', 'S')
                payload = sig.get('payload', '')

                pkt = IP(dst=TARGET_IP)/TCP(sport=sport, dport=dport, flags=flags)/Raw(load=payload)

            else:
                print(f"[!] Unknown protocol in attack: {sig['protocol']}")
                continue

            send(pkt, iface=INTERFACE, verbose=False)

            print(f"→ Sent {attack_type} packet:")
            for k, v in sig.items():
                print(f"   {k}: {v}")

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.\n")

def show_menu():
    while True:
        print("\n========== KDD99 ATTACK SIMULATOR ==========")
        print("1. DoS (ICMP flood)")
        print("2. Probe (TCP FTP scan)")
        print("3. R2L (Login attempt)")
        print("4. U2R (Privilege escalation)")
        print("5. Exit")
        choice = input("Select an attack to send (1-5): ")

        options = {
            '1': 'DoS',
            '2': 'Probe',
            '3': 'R2L',
            '4': 'U2R'
        }

        if choice == '5':
            print("Goodbye!")
            break
        elif choice in options:
            send_attack_loop(options[choice])
        else:
            print("Invalid selection. Try again.")

if __name__ == "__main__":
    show_menu()
