import argparse
import datetime
import textwrap

from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Simple educational packet sniffer.\n\n"
            "Use this only on networks you own or have explicit permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff on (leave empty for default).",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited until Ctrl+C).",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["ip", "tcp", "udp", "icmp"],
        help="Filter by protocol (simple client-side filter).",
    )
    parser.add_argument(
        "--show-payload",
        action="store_true",
        help="Show packet payload (hex + ASCII, truncated).",
    )
    parser.add_argument(
        "--bpf-filter",
        help=(
            "Optional BPF filter string passed to Scapy/libpcap, e.g. "
            "'tcp port 80' or 'host 8.8.8.8'."
        ),
    )

    return parser.parse_args()


def format_payload(raw_layer: Raw, max_len: int = 64) -> str:
    if not raw_layer:
        return ""

    data = bytes(raw_layer.load)[:max_len]
    hex_part = " ".join(f"{b:02x}" for b in data)
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

    return f"HEX: {hex_part}\nASCII: {ascii_part}"


def proto_name(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        return "IP"
    if pkt.haslayer(Ether):
        return "Ethernet"
    return "UNKNOWN"


def passes_simple_protocol_filter(pkt, proto: str | None) -> bool:
    if not proto:
        return True

    if proto == "tcp":
        return pkt.haslayer(TCP)
    if proto == "udp":
        return pkt.haslayer(UDP)
    if proto == "icmp":
        return pkt.haslayer(ICMP)
    if proto == "ip":
        return pkt.haslayer(IP) or pkt.haslayer(IPv6)

    return True


def packet_handler(pkt, args: argparse.Namespace) -> None:
    if not passes_simple_protocol_filter(pkt, args.protocol):
        return

    ts = datetime.datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]

    src_ip = dst_ip = "-"
    src_port = dst_port = "-"

    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

    if TCP in pkt:
        l4 = pkt[TCP]
        src_port, dst_port = l4.sport, l4.dport
    elif UDP in pkt:
        l4 = pkt[UDP]
        src_port, dst_port = l4.sport, l4.dport

    length = len(pkt)
    proto = proto_name(pkt)

    line = (
        f"[{ts}] {proto:<7} {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"len={length}"
    )
    print(line)

    if args.show_payload and Raw in pkt:
        payload_str = format_payload(pkt[Raw])
        if payload_str:
            print(
                textwrap.indent(payload_str, prefix="    "),
            )
            print()


def main() -> None:
    args = parse_args()

    print(
        "Educational Packet Sniffer\n"
        "====================================\n"
        "Use this only on networks where you\n"
        "have explicit permission to capture\n"
        "traffic (e.g. your own lab).\n"
        "Press Ctrl+C to stop.\n"
    )

    try:
        sniff(
            iface=args.interface,
            prn=lambda pkt: packet_handler(pkt, args),
            count=args.count if args.count > 0 else 0,
            filter=args.bpf_filter,
            store=False,
        )
    except PermissionError:
        print(
            "\n[!] Permission error: you probably need to run this script "
            "with administrator/root privileges.\n"
            "   On Windows, run PowerShell as Administrator.\n"
            "   On Linux/macOS, try: sudo python sniffer.py ...\n"
        )
    except OSError as e:
        print(
            f"\n[!] OS error while starting sniffer: {e}\n"
            "   Make sure a packet capture driver is installed (e.g. Npcap/WinPcap on Windows)\n"
            "   and that the interface name is correct.\n"
        )
    except KeyboardInterrupt:
        print("\nStopping capture (Ctrl+C pressed).")


if __name__ == "__main__":
    main()

