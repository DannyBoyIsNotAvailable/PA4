"""Send a file as numbered UDP multicast packets."""

import argparse
import hashlib
import ipaddress
import math
from pathlib import Path
import socket
import struct
import sys
import time
import uuid


GROUP = "239.1.1.4"
PORT = 5504
CHUNK_SIZE = 1024
MAGIC = b"PA4\x01"
# Magic/version, transfer ID, file size, chunk index, SHA-256, UTF-8 name length.
HEADER = struct.Struct("!4s16sQQ32sB")


def send_file(args):
    name = args.file.name.encode("utf-8")
    if not 1 <= len(name) <= 255 or any(c in args.file.name for c in "/\\:\x00"):
        raise ValueError("unsupported filename")

    interface = ipaddress.IPv4Address(args.interface)
    group = ipaddress.IPv4Address(args.group)
    if not group.is_multicast:
        raise ValueError("--group must be an IPv4 multicast address")
    destination = (str(group), args.port)
    # 本次传输 ID，各轮复用
    transfer_id = uuid.uuid4().bytes

    with args.file.open("rb") as source, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # 先算整文件哈希
        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
            size += len(block)
        checksum = digest.digest()
        count = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)

        # 指定组播出口
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface.packed)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
        print(f"Sending {args.file.name!r} ({size} bytes, {count} chunks) to {group}:{args.port}")
        print(f"SHA-256 {digest.hexdigest()}")

        round_number = 0
        # 按轮重发，供迟加入补块
        while args.rounds == 0 or round_number < args.rounds:
            source.seek(0)
            for index in range(count):
                data = source.read(CHUNK_SIZE)
                expected = min(CHUNK_SIZE, size - index * CHUNK_SIZE)
                if len(data) != expected:
                    raise OSError("source file size changed during transfer")
                # 包头 + 文件名 + 数据块
                header = HEADER.pack(MAGIC, transfer_id, size, index, checksum, len(name))
                sock.sendto(header + name + data, destination)
                # 控制发包间隔
                if args.delay:
                    time.sleep(args.delay)
            if source.read(1):
                raise OSError("source file size changed during transfer")
            round_number += 1
            print(f"Round {round_number} sent ({count} chunks)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--interface", required=True, help="IPv4 address of the sender")
    parser.add_argument("--group", default=GROUP)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--rounds", type=int, default=2, help="file rounds to send (0 = until Ctrl+C)")
    parser.add_argument("--delay", type=float, default=0.005, help="seconds between packets")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.rounds < 0 or not math.isfinite(args.delay) or args.delay < 0:
        parser.error("use a valid UDP port, nonnegative rounds, and a finite nonnegative delay")

    try:
        send_file(args)
    except KeyboardInterrupt:
        print("Sender stopped")
    except (OSError, ValueError) as error:
        print(f"Sender error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
