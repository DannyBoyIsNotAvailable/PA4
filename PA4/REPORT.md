# COMP 535 PA4 — Reliable Multicast File Sharing

## Protocol overview

The sender splits each input file into chunks and distributes them over UDP multicast. The default chunk size is 1,024 bytes and can be changed with the sender's -c option. Periodic announcements identify each file and provide its size, chunk count, chunk size, and checksum.

## Design choices

**Selective retransmission.** The sender transmits the original chunks in sequence and stays available to serve recovery requests. When a receiver makes no progress for 500 ms, it groups consecutive missing sequence numbers into ranges and sends them in negative acknowledgments (NACKs). The sender combines requests for chunks that are already queued and multicasts the requested data, so one retransmission can serve multiple receivers. Periodic announcements let late or restarted receivers discover the files and request the chunks they missed.

**Direct-to-disk reassembly.** A receiver writes each accepted chunk at the offset given by its sequence number multiplied by the chunk size. It keeps one byte of receipt state per chunk. This supports out-of-order delivery without buffering the whole file in memory. The trade-offs are file seeks during reassembly and a sequential read of the reconstructed file for final verification.

## Integrity and statistics

The receiver checks each chunk before writing it. A chunk that fails validation remains missing and can be requested again. After reassembly, the receiver reads the file back and compares its checksum with the announced value. A file is marked complete only after its checksum matches. The programs report transmissions, retransmissions, NACKs, simulated drops, and recovered chunks. Receiver throughput is calculated from unique chunks accepted and the elapsed time from the first accepted chunk to the end of verification.

## Evaluation

These measurements were collected on one Windows machine using WSL, before the final change to the checksum failure path. Cross-machine LAN operation remains to be verified. A separate receiver test fed deterministic packets for valid and mismatched checksums on both empty and nonempty files. The receiver exited with status 0 on a match and status 1 on a mismatch. After rebuilding the receiver in WSL, we repeated the basic multicast transfer with both files. The sender sent 79 original data packets with zero retransmissions, and both receivers produced copies with matching SHA-256 hashes.

| Scenario | Observed result |
| --- | --- |
| Basic multicast | Both receivers reconstructed the text and JPEG files. The sender transmitted 79 original data packets with zero retransmissions. |
| File integrity | Both receivers matched the sender's checksums for the text file (bd89296e) and JPEG (bb4e9ce6). Independent SHA-256 checks also matched all received copies to their originals. |
| Late receiver | Both receivers reconstructed the 16 MiB file with matching SHA-256 hashes. The late receiver sent eight NACKs and accepted 121,175 missing chunks through retransmission. |
| Simulated packet loss | Receiver 2 discarded JPEG chunks 18, 38, and 58. It sent one NACK, recovered all three chunks, and verified both files. |
| Receiver failure | Receiver 2 was stopped during the transfer. The sender handled five NACKs from Receiver 1, which reconstructed all 65,536 chunks and matched the original file's SHA-256 hash. |

The late-join run used 128-byte chunks. The sender sent 131,072 original data packets and 725,034 retransmission packets, about 5.53 retransmissions per original packet. The receiver that started before the sender also relied on retransmission for 115,468 chunks. This run demonstrated successful recovery with substantial retransmission overhead.
