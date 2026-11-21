#include <stdio.h>     
#include <stdlib.h>     
#include <string.h>     
#include <errno.h>      
#include <sys/stat.h>   
#include <arpa/inet.h>  
#include "protocol.h"
#include "multicast.h"
#include <time.h>
#include <unistd.h>

// receiver收到的文件放在这个directory
#define OUT_DIR "received_files" // where the rebuilt files are saved
#define RECV_BUFFER_BYTES (8 * 1024 * 1024)
#define NACK_WAIT_MS 500 // wait for how long to send NACK
#define LOG_LIMIT 10 // how many line to be printed from log

typedef struct {
    int hasAnnounce;
    char name[MAX_NAME_LEN];
    uint32_t size;
    uint32_t total_chunks;
    uint32_t chunk_size;
    uint32_t file_checksum;  // expected checksum of the whole file
    FILE *fp; // use to write out
    uint8_t *receivedSeq; // receivedSeq[seq] == 1 means we received this seq
    uint32_t numReceived; // have received how many diff chunk
    int complete; // collect all chunk or not
} rfile_t;



// Global state of the receiver
static rfile_t files[MAX_FILES];
static int numFiles = 0; // 0 until been announced by the 1st ANNOUNCE packet
static int drop_every = 0; // 每多少数据丢一次
static uint32_t receiver_id; 
static long long last_new_ms = 0; // the time for last wrote segment


// Statistics
static unsigned long stat_data = 0;  // num of DATA packets written to a file
static unsigned long stat_duplicate = 0;  // num of chunk we already had
static unsigned long stat_unknown   = 0;  // num of DATA pkt for a file not announced yet
static unsigned long stat_bad  = 0;  // num of packets with wrong sizes/values
static unsigned long stat_original = 0; // number of packet we originally received (not include duplicate)
static unsigned long stat_dropped = 0; // number of packet we dropped 
static unsigned long stat_recovered = 0; // number of packet that ask for retransmit
static unsigned long stat_nacks = 0; // number of the NACK packet sent
static unsigned long stat_checksum_error = 0;  // chunks whose checksum did not match
static long long first_ms = 0;


static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


// handle an ANNOUNCE packet: remember the file and create the output file
static void handle_announce(const pkt_announce_t *a, int n) {
    if ((int) sizeof(pkt_announce_t) != n) {
        stat_bad++;
        return;
    }

    uint16_t id = ntohs(a->file_id);
    uint16_t total = ntohs(a->num_files);
    if (total == 0 || id >= total || total > MAX_FILES) {
        stat_bad++;
        return;
    }

    numFiles = total;
    rfile_t *f = &files[id];
    if (f->hasAnnounce) return; // already have this ANNOUNCE packet

    f->size = ntohl(a->file_size);
    f->total_chunks = ntohl(a->total_chunks);
    f->chunk_size   = ntohl(a->chunk_size);
    if (f->chunk_size == 0 || f->chunk_size > MAX_CHUNK_SIZE) {
        stat_bad++;
        return;
    }
    f->file_checksum = ntohl(a->file_checksum);

    // copy the name of file
    memcpy(f->name, a->name, MAX_NAME_LEN);
    f->name[MAX_NAME_LEN - 1] = '\0'; // make sure it end with '\0'

    char path[MAX_NAME_LEN + 32];
    snprintf(path, sizeof(path), "%s/%s", OUT_DIR, f->name); // write the path
    f->fp = fopen(path, "wb+"); // // create (or empty) the file for writing
    if (f->fp == NULL) {
         perror(path); 
         exit(1); 
    }

    f->receivedSeq = calloc(f->total_chunks > 0 ? f->total_chunks : 1, 1);
    if (f->receivedSeq == NULL) {
        perror("calloc");
        exit(1);
    }

    f->numReceived = 0;
    f->complete = (f->total_chunks == 0); // an empty file is complete at beginning
    f->hasAnnounce = 1;
    last_new_ms = now_ms(); 

    printf("file %u/%u announced: %s, %u bytes, %u chunks of %u bytes\n",
           id, total, f->name, f->size, f->total_chunks, f->chunk_size);

}

// Read the rebuilt file back from disk, compute its checksum and
// compare it with the one the sender announced.
static void verify_file(rfile_t *f) {
    uint8_t  block[65536];
    size_t   n;
    uint32_t c = CHECKSUM_INIT;

    rewind(f->fp);     // read from the start
    while ((n = fread(block, 1, sizeof(block), f->fp)) > 0) {
        c = checksum_update(c, block, (uint32_t)n);
    }

    printf("Verify %s: original checksum %08x, received checksum %08x -> %s\n",
           f->name, f->file_checksum, c, c == f->file_checksum ? "OK" : "MISMATCH");
}

// handle a data packet, write the chunk to its place in file f->fp
static void handle_data(const pkt_data_t *d, int n) {
    if (n < (int)sizeof(pkt_data_t)) {
        stat_bad++;
        return;
    }

    uint16_t id  = ntohs(d->file_id);
    uint16_t len = ntohs(d->data_len);
    uint32_t seq = ntohl(d->seq);

    if (id >= MAX_FILES) {
        stat_bad++;
        return;
    }
    rfile_t *f = &files[id]; // get the file info

    // check if we have been announced yet
    if (!f->hasAnnounce) {
        stat_unknown++;
        return;
    }

    // check the validation
    if (seq >= f->total_chunks || len > f->chunk_size || n != (int)sizeof(pkt_data_t) + len) {
        stat_bad++;
        return;
    }

    int retransmit = (d->hdr.flags & RETRANSMIT_FLAG) != 0; // check if this is retransmit packet

     if (!retransmit) {
        stat_original++;
        if (drop_every > 0 && stat_original % drop_every == 0) {
            stat_dropped++;
            if (stat_dropped <= LOG_LIMIT) {
                printf("test drop: file %u chunk %u\n", id, seq);
            }
            return;
        }
    }


    // receive duplicate data packet (seq:i)
    if (f->receivedSeq[seq]) {stat_duplicate++; return;}


    // Chunk checksum: a corrupted chunk is dropped and will be NACKed later.
    if (checksum_update(CHECKSUM_INIT, d->data, len) != ntohl(d->checksum)) {
        stat_checksum_error++;
        printf("Corrupted chunk discarded: file %u chunk %u\n", id, seq);
        return;
    }


    long offset = (long) seq * f->chunk_size;
    fseek(f->fp, offset, SEEK_SET); // move the ptr to the start write position
    if (fwrite(d->data, 1, len, f->fp) != len) {
        perror("fwrite");
        exit(1);
    }


    if (stat_data == 0) {
        first_ms = now_ms(); 
        printf("First chunk received: file %u chunk %u\n", id, seq);
    }
    if (retransmit) {
        stat_recovered++;
        if (stat_recovered <= LOG_LIMIT) {
            printf("Recovered: file %u chunk %u (retransmission)\n", id, seq);
        }
    }

    // successfully write the seq: i packet into the disk
    f-> receivedSeq[seq] = 1;
    f-> numReceived++;
    stat_data++;
    last_new_ms = now_ms();

    if (f->numReceived == f->total_chunks) { // have received all the chunks
        f->complete = 1;
        fflush(f->fp); // ensure everything on disk
        printf("file %u complete: %s (%u chunks)\n",
               id, f->name, f->total_chunks);
        verify_file(f); 
    }

}




static int allDone(void) {
    if (numFiles == 0) return 0;      // no ANNOUNCE yet
    for (int i=0; i<numFiles; i++) {
        if (!files[i].complete) return 0;
    }
    return 1;
}


static void send_nack(mcast_t *ctrl) {
    for (int i=0; i<numFiles; i++) {
        rfile_t *f = &files[i];
        if (!f->hasAnnounce || f->complete) continue;
        int packets = 0, ranges = 0;
        uint32_t seq = 0;

        while (seq < f->total_chunks) {
            // one NACK packet per loop
            pkt_nack_t k;
            memset(&k, 0, sizeof(k));
            k.hdr.magic   = htons(PROTO_MAGIC);
            k.hdr.type    = PACKET_NACK;
            k.receiver_id = htonl(receiver_id);
            k.file_id     = htons((uint16_t)i);

            // go through receivedSeq[] every sequence of 0 become one range eg 1100011
            int j = 0; // 第几个range 
            while (seq < f->total_chunks && j < MAX_NACK_RANGES) {
                if (f->receivedSeq[seq]) {
                    seq++;
                    continue;
                } // have it 
                uint32_t start = seq;
                while (seq < f->total_chunks && !f->receivedSeq[seq]) {
                    seq++;
                }
                k.ranges[j].start = htonl(start);
                k.ranges[j].end = htonl(seq - 1);
                j++;
            }
            if (j == 0) break; // is complete (actually we don't need to check it once again)
            
            // get enough range 
            k.num_ranges = htons((uint16_t) j);
            multicast_send(ctrl, &k, 12 + j * (int)sizeof(nack_range_t));
            packets++;
            ranges += j;
            stat_nacks++;
            
        }
        // print the NACK send for each file
        printf("send NACK for file %d (%s): %u chunk(s) missing in %d range(s), sent %d NACK packet(s)\n",
               i, f->name, f->total_chunks - f->numReceived, ranges, packets);

    }
}


int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0); // print each line at once, even into a log file

    // command line: optional "-d N" for the packet loss test (N is every N packet)
    if (argc == 3 && strcmp(argv[1], "-d") == 0) {
        drop_every = atoi(argv[2]);
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [-d N]   (-d N: drop every N-th original chunk)\n", argv[0]);
        exit(1);
    }


    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    receiver_id = (uint32_t)rand(); // 生成随机的receiver id

    // prepare the output folder
    if (mkdir(OUT_DIR, 0755) != 0 && errno != EEXIST) {
        perror(OUT_DIR);  // 0755 represent 7 : self read and write, 5 : others can read
        exit(1);
    }

    // join the multicast group
    mcast_t *m = multicast_init(MCAST_GROUP, DATA_PORT, DATA_PORT);

    // A bigger socket buffer lets us survive short burst from sender
    int bufsize = RECV_BUFFER_BYTES;
    setsockopt(m->sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)); // modify the socket buffer size

    multicast_setup_recv(m);
    mcast_t *ctrl = multicast_init(MCAST_GROUP, CTRL_PORT, CTRL_PORT);  // NACKs go out here (only send)
    printf("receiver id %08x joined %s at port %d, waiting for files...\n",receiver_id, MCAST_GROUP, DATA_PORT);
    if (drop_every > 0) {
        printf("Test: dropping every %dth original chunk\n", drop_every);
    }
    
    
    // receive until every file is complete
    uint8_t buf[MAX_PACKET_SIZE];
    long long last_nack_ms = 0;

    while (!allDone()) {
        long long now = now_ms();
        if (now - last_new_ms >= NACK_WAIT_MS && now - last_nack_ms >= NACK_WAIT_MS) {
            send_nack(ctrl);
            last_nack_ms = now; // every NACK_WAIT_MS send the NACK
        }

        if (multicast_check_receive_timeout(m, 100) <= 0) {
            continue;    // nothing for 100 ms
        }

        int n = multicast_receive(m, buf, sizeof(buf)); // n is the size of packet

        // Every packet starts with general header
        if (n < (int) sizeof(pkt_header_t)) {
            stat_bad++; continue;
        }
        pkt_header_t *h = (pkt_header_t *) buf;
        if (ntohs(h->magic) != PROTO_MAGIC) continue; // this is not our packet


        switch (h->type) {
            case PACKET_ANNOUNCE:
            handle_announce((pkt_announce_t *)buf, n); 
            break;
            case PACKET_DATA:
            handle_data((pkt_data_t *)buf, n);
            break;
            default:
            break;
        }
    }

    printf("Receiving done: %d files, %lu chunks, %lu dup, %lu early, %lu bad, %lu corrupt\n",
           numFiles, stat_data, stat_duplicate, stat_unknown, stat_bad, stat_checksum_error); 

    printf("Recovery: %lu dropped on purpose, %lu recovered by retransmission, %lu NACKs sent\n",
           stat_dropped, stat_recovered, stat_nacks);

    long long elapsed = now_ms() - first_ms;
    printf("Time: %lld ms from first chunk to all files verified, throughput %.0f packets/s\n", elapsed, stat_data * 1000.0 / elapsed);

    for (int i = 0; i < numFiles; i++) {
        fclose(files[i].fp);
        free(files[i].receivedSeq);
    }
    multicast_destroy(m);
    multicast_destroy(ctrl);
    return 0;
}
