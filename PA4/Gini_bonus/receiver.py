"""Receive and verify a numbered UDP multicast file."""

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
import struct
import sys
from tempfile import NamedTemporaryFile
import time


GROUP = "239.1.1.4"
PORT = 5504
CHUNK_SIZE = 1024
MAGIC = b"PA4\x01"
# Magic/version, transfer ID, file size, chunk index, SHA-256, UTF-8 name length.
HEADER = struct.Struct("!4s16sQQ32sB")


def parse_packet(packet):
    if len(packet) < HEADER.size:
        return None
    magic, transfer_id, size, index, checksum, name_length = HEADER.unpack_from(packet)
    name_end = HEADER.size + name_length
    count = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    if magic != MAGIC or not name_length or len(packet) < name_end or index >= count:
        return None
    expected = min(CHUNK_SIZE, size - index * CHUNK_SIZE)
    if len(packet) - name_end != expected:
        return None
    try:
        name = packet[HEADER.size:name_end].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if name in (".", "..") or any(c in name for c in "/\\:\x00"):
        return None
    return transfer_id, (name, size, checksum, count), index, packet[name_end:]


class Transfer:
    def __init__(self, output_dir, metadata):
        self.metadata = metadata
        self.name, self.size, self.checksum, self.count = metadata
        self.destination = output_dir / self.name
        self.file = NamedTemporaryFile(mode="w+b", dir=output_dir, suffix=".part", delete=False)
        self.partial_path = Path(self.file.name)
        self.chunks = set()

    def add(self, index, data):
        if index not in self.chunks:
            self.file.seek(index * CHUNK_SIZE)
            self.file.write(data)
            self.chunks.add(index)

    def verify_and_save(self):
        self.file.seek(0)
        digest = hashlib.sha256()
        for block in iter(lambda: self.file.read(64 * 1024), b""):
            digest.update(block)
        self.file.close()

        print(f"Expected SHA-256 {self.checksum.hex()}")
        print(f"Received SHA-256 {digest.hexdigest()}")
        if digest.digest() != self.checksum:
            print(f"Checksum failed for {self.name!r}. Waiting for another round.")
            return False
        os.replace(self.partial_path, self.destination)
        print(f"Verified {self.destination} ({self.size} bytes, {self.count} chunks)")
        return True

    def close(self):
        self.file.close()
        self.partial_path.unlink(missing_ok=True)


def receive_files(args):
    interface = ipaddress.IPv4Address(args.interface)
    group = ipaddress.IPv4Address(args.group)
    if not group.is_multicast:
        raise ValueError("--group must be an IPv4 multicast address")
    membership = group.packed + interface.packed
    args.output_dir.mkdir(parents=True, exist_ok=True)
    active = {}
    completed = set()
    valid_packets = 0
    last_report = time.monotonic()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.bind(("", args.port))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        print(f"Joined {group}:{args.port} on {interface}")

        try:
            while True:
                packet, source = sock.recvfrom(65535)
                parsed = parse_packet(packet)
                if parsed is None:
                    continue
                transfer_id, metadata, index, data = parsed
                key = (source, transfer_id)
                valid_packets += 1
                now = time.monotonic()
                if now - last_report >= 2:
                    print(f"Still receiving on {interface}. Valid packets: {valid_packets}")
                    last_report = now
                if key in completed:
                    continue

                transfer = active.get(key)
                if transfer is None:
                    transfer = active[key] = Transfer(args.output_dir, metadata)
                    print(
                        f"Receiving {transfer.name!r} from {source[0]}. "
                        f"First chunk: {index + 1}/{transfer.count}"
                    )
                if transfer.metadata != metadata:
                    continue
                transfer.add(index, data)
                if len(transfer.chunks) == transfer.count:
                    verified = transfer.verify_and_save()
                    transfer.close()
                    del active[key]
                    if verified:
                        completed.add(key)
                        if args.once:
                            return
        except KeyboardInterrupt:
            print("Receiver stopped")
        finally:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership)
            print(f"Left {group} on {interface}. Valid packets received: {valid_packets}")
            for transfer in active.values():
                transfer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface", help="IPv4 address of this receiver")
    parser.add_argument("--group", default=GROUP)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--output-dir", type=Path, default=Path("received_files"))
    parser.add_argument("--once", action="store_true", help="leave after verifying one file")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("use a valid UDP port")

    try:
        receive_files(args)
    except (OSError, ValueError) as error:
        print(f"Receiver error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
