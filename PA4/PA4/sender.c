#include <stdio.h>    
#include <stdlib.h>  
#include <string.h>   
#include "protocol.h"
#include <time.h>       
#include <unistd.h>     
#include <arpa/inet.h>  
#include "multicast.h"

#define ANNOUNCE_INTERVAL 1000 // announce every 1s (discuss in report)
#define SEND_RATE 10000 // how many packet per second

typedef struct {
    char name[MAX_NAME_LEN]; // filename
    FILE *fp;
    uint32_t size;  // file size (byte)
    uint32_t total_chunks;
    uint32_t file_checksum; // checksum of whole file
    uint8_t *need; // need[seq] == 1: a receiver asked for chunk seq again
    uint32_t need_count; // how many entries of need[] are 1
    uint32_t rtx_cursor; // where to continue looking in need[]

} file_info_t;


// Global status of the sender
static int num_files = 0;
static uint32_t chunk_size = DEFAULT_CHUNK_SIZE;
static file_info_t files[MAX_FILES]; // sender use this array to track the info of each file
// Position of the first pass (every chunk sent once, in order).
static int next_file = 0;
static uint32_t next_seq  = 0;

// Statistics.
static unsigned long stat_nacks = 0;  // NACK packets received



// get current time in milliseconds (clock won't go backward, this range is very big so its enough)
// will use to calculate the RTT, throughput...
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static long long now_us(void) { 
    struct timespec ts;
     clock_gettime(CLOCK_MONOTONIC, &ts);
      return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
 }



static void addFile(const char* path) {
    FILE *fp = fopen(path, "rb"); // "rb" = read binary
    if (fp == NULL) {
        perror(path);
        exit(1); // no such file
    }
    fseek(fp, 0, SEEK_END); // jump to the end of file 
    long size = ftell(fp);  // and ask the position (this is the size of file)
    rewind(fp); // back to the start

    // Keep only the part after the last "/" eg: ..../train.csv -> keep train.csv
    const char *slash = strrchr(path, '/'); // searching from the right side looking for 1st slash
    const char *name = (slash == NULL) ? path : slash + 1; 

    file_info_t *f = &files[num_files]; // next empty entry of the file_info array, f is the pointer
    snprintf(f->name, sizeof(f->name), "%s", name); 
    f->fp =fp;
    f->size = (uint32_t) size;
    f->total_chunks = (f->size + chunk_size -1) / chunk_size; // 这里这样算是向上取整

    uint8_t block[65536]; // checksum of whole file: read it in block (64KB) and feed every block
    size_t n;
    f->file_checksum = CHECKSUM_INIT;
    while ((n = fread(block, 1, sizeof(block), fp)) > 0) {
        f->file_checksum = checksum_update(f->file_checksum, block, (uint32_t)n);
    }
    rewind(fp); // back to the start

    f->need         = calloc(f->total_chunks, 1);  // all 0 = nothing requested yet
    f->need_count   = 0;
    f->rtx_cursor   = 0;
        
    num_files++;
}

// when the user give the command line in a incorrect way, 
// usage() will show the problem and exit()
static void usage(const char *method) {
    fprintf(stderr, "usage: %s -c chunk_size file1 file2 file3 ...\n", method);
    fprintf(stderr, "chunk size in bytes (1 to %d, default %d)\n", MAX_CHUNK_SIZE, DEFAULT_CHUNK_SIZE);
    exit(1);
}

// Fill the common header that starts every packet
static void fill_header(pkt_header_t *h, uint8_t type, uint8_t flags) {
    h->magic      = htons(PROTO_MAGIC);
    h->type       = type;
    h->flags      = flags;
}

// send the chunk of one certain file to all muticast hosts
static int send_chunk(mcast_t *m, int file_id, uint32_t seq, uint8_t flags) {
    file_info_t *f = &files[file_id];

    uint8_t buf[MAX_PACKET_SIZE]; // room for header + largest chunk
    pkt_data_t *pkt = (pkt_data_t *) buf; // 这里就是前面定义的pkt->data, 把这块内存当成DATA packet用

    // where the chunk starts in the file and how many byte it has
    long     offset = (long)seq * chunk_size;
    uint32_t len    = chunk_size;
    if (offset + len > f->size) {
        len = f->size - (uint32_t)offset;  // the last chunk is shorter
    }

    fseek(f->fp, offset, SEEK_SET); // move the ptr to the offset position
    // read the chunk from file into the data part of the packet (f->fp  read to pkt->data)
    if (fread(pkt->data, 1, len, f->fp) != len) {
        fprintf(stderr, "read error in %s at chunk %u\n", f->name, seq);
        exit(1);
    }

    // fill the data header
    fill_header(&pkt->hdr, PACKET_DATA, flags);
    pkt->file_id      = htons((uint16_t)file_id);
    pkt->data_len     = htons((uint16_t)len);
    pkt->seq          = htonl(seq);
    pkt->total_chunks = htonl(f->total_chunks);
    pkt->checksum     = htonl(checksum_update(CHECKSUM_INIT, pkt->data, len));

    // sizeof(pkt_data_t) haven't count the data part = 24 byte
    return multicast_send(m, pkt, sizeof(pkt_data_t) + len);
}

// send the ANNOUNCE packet that describes the "file_id"th file 
static void send_announce(mcast_t *m, int file_id) {
    file_info_t *f = &files[file_id];
    pkt_announce_t pkt;
    memset(&pkt, 0, sizeof(pkt)); // start from all zero

    fill_header(&pkt.hdr, PACKET_ANNOUNCE, 0);
    pkt.file_id      = htons((uint16_t)file_id);
    pkt.num_files    = htons((uint16_t)num_files);
    pkt.file_size    = htonl(f->size);
    pkt.total_chunks = htonl(f->total_chunks);
    pkt.chunk_size   = htonl(chunk_size);
    pkt.file_checksum = htonl(f->file_checksum);
    snprintf(pkt.name, sizeof(pkt.name), "%s", f->name);

    multicast_send(m, &pkt, sizeof(pkt));
}

// Send one ANNOUNCE for every file.
static void announce_all(mcast_t *m)
{
    for (int i = 0; i < num_files; i++) {
        send_announce(m, i);
    }
}

// NACK arrived: mark those needed chunk in need[]
static void handle_nack(const pkt_nack_t *k) {
    uint16_t id = ntohs(k->file_id);
    uint16_t num_ranges = ntohs(k->num_ranges);

    if (id >= num_files || num_ranges > MAX_NACK_RANGES) return;
    file_info_t *f = &files[id];
    uint32_t asked = 0; // count how many seq the NACK ask for retransmit (need to count from each range)
    for (int r = 0; r < num_ranges; r++) {
        uint32_t start = ntohl(k->ranges[r].start);
        uint32_t end   = ntohl(k->ranges[r].end);
        if (start > end || end >= f->total_chunks) continue;   // invalid range

        for (uint32_t seq = start; seq <= end; seq++) {
            asked++;
            if (!f->need[seq]) {// there may another recevier already send request for it
                f->need[seq] = 1;
                f->need_count++;
            }
        }
    }
    stat_nacks++;

    printf("[sender] NACK from receiver %08x: file %u (%s), %u chunk(s) in %u range(s), first [%u-%u]\n",
           ntohl(k->receiver_id), id, f->name, asked, num_ranges,
           ntohl(k->ranges[0].start), ntohl(k->ranges[0].end));
}


// Read every packet waiting on the control channel.
// Waits at most timeout_ms for the first one.
static void poll_ctrl(mcast_t *ctrl, int timeout_ms) {
    uint8_t buf[sizeof(pkt_nack_t)];  // a NACK is the only packet sent to us

    // 检查port里面有没有NACK, if exist -> poll out all of them until its empty
    while (multicast_check_receive_timeout(ctrl, timeout_ms) > 0) {
        timeout_ms = 0; // after the first, only take what is waiting
        int n = multicast_receive(ctrl, buf, sizeof(buf));
        pkt_header_t *h = (pkt_header_t *)buf;
        if (n >= (int)sizeof(pkt_header_t) + 8 &&      // header + id + file_id + num_ranges
            ntohs(h->magic) == PROTO_MAGIC && h->type == PACKET_NACK) {
                handle_nack((pkt_nack_t *)buf);
            }
    }
}


// Priority of sending: choose the next chunk to send: requested retransmissions first,
// then the next chunk of the first pass. Returns 0 if there is nothing to send.
static int pick_next(int *file_id, uint32_t *seq, uint8_t *flags) {
    // 1: retransmissions
    for (int i=0; i<num_files; i++) {
        file_info_t *f = &files[i];
        if (f->need_count == 0) continue; // this files has no request for retransmit

        while (!f->need[f->rtx_cursor]) {
            f->rtx_cursor = (f->rtx_cursor + 1) % f->total_chunks; // move to next position and check
        }
        *file_id = i;
        *seq = f->rtx_cursor;
        *flags = RETRANSMIT_FLAG;
        // no longer requested
        f->need[*seq] = 0; 
        f->need_count--;
        return 1;
    }

    // 2: when there no chunk need to be retransmitted (move to the first pass)
    while (next_file < num_files && next_seq >= files[next_file].total_chunks) {
        next_file++;
        next_seq = 0;
    }
    if (next_file < num_files) {
        *file_id = next_file;
        *seq = next_seq++; // give the seqNum then add by 1
        *flags = 0;
        return 1;
    }

    return 0; // first pass finished and no retransmission request

}



int main(int argc, char *argv[]) {

    setvbuf(stdout, NULL, _IOLBF, 0);  // print each line at once, even into a log file

    // read the commad line
    const char *paths[MAX_FILES]; // file names found on the command line
    int num_paths = 0;

    // argv[0] is the method name
    for (int i=1; i<argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 >= argc) usage(argv[0]); // there no arg after the -c just terminate
            i++;
            int c = atoi(argv[i]); // convert the ASCII to integer eg: "67" -> 67
            if (c <= 0 || c > MAX_CHUNK_SIZE) {
                fprintf(stderr, "invalid chunk size: %s\n", argv[i]);
                usage(argv[0]);
            }
            chunk_size = (uint32_t) c; // 可以选择自己的chunk size不用default
        } else {
            if (num_paths >= MAX_FILES) {
                fprintf(stderr, "too many files :( (max %d)\n", MAX_FILES);
                exit(1);
            }
            paths[num_paths++] = argv[i]; // remember the file path, will open it later
        }
    }

    if (num_paths == 0) usage(argv[0]); // terminate

    for (int j=0; j<num_paths; j++) {
        addFile(paths[j]);
    }

    // print out what will be sent (chunk size and number of files)
    printf("[sender] chunk size = %u bytes, %d files\n", chunk_size, num_files);
    // print out those info we collected at addFile()
    for (int i = 0; i < num_files; i++) {
        printf("[sender]   file %d: %-20s %10u bytes  %8u chunks  checksum %08x\n",
               i, files[i].name, files[i].size, files[i].total_chunks, files[i].file_checksum);
    }

    // send every chunk for every file 

    // setup broadcast socket
    mcast_t *m = multicast_init(MCAST_GROUP, DATA_PORT, DATA_PORT);
    mcast_t *ctrl = multicast_init(MCAST_GROUP, CTRL_PORT, CTRL_PORT); // NEW: NACKs from receivers arrive here
    multicast_setup_recv(ctrl);                                         // NEW

    unsigned long total_packets = 0;
    unsigned long total_bytes = 0;
    unsigned long announce_rounds = 0;
    unsigned long total_retransmits = 0;   // NEW: chunks sent again because of a NACK

    announce_all(m);
    announce_rounds++;
    long long last_announce = now_ms(); // use to count the time that we need to send the next announce

    long long start_ms = now_ms(); // when sending started
    int busy = 1;  // 1 while there is something to send
    long long pace_start = now_us(); // rate limiting: when counting started
    unsigned long pace_sent = 0;   // rate limiting: packets sent since then

    // send the packet in order (不是交错发，交错发会比较fair)
    while (1) {     // NEW: runs until Ctrl+C
        poll_ctrl(ctrl, 0);   // NEW: take any NACKs that are waiting

        // During the entire sending process, every announce_interval describe the files
        // the period is long enough so it's safe to write it here
        if (now_ms() - last_announce >= ANNOUNCE_INTERVAL) {
            announce_all(m);
            announce_rounds++;
            last_announce = now_ms();
        }

        int i; uint32_t seq; uint8_t flags;                       
        if (!pick_next(&i, &seq, &flags)) {  // nothing to send
            if (busy) {   // just became idle
                printf("Done: sent %lu packets, %lu bytes, %lu retransmitted, %lu NACKs, %lld ms\n",
                       total_packets, total_bytes, total_retransmits, stat_nacks,
                       now_ms() - start_ms);                     
                busy = 0;                                        
            }
            poll_ctrl(ctrl, 100);  // wait up to 100 ms for a NACK
            pace_start = now_us();                                
            pace_sent = 0;                                        
            continue; 
        }                                   
        busy = 1;                                                 

        // NEW: rate limit, at most SEND_RATE packets per second
        while ((long long)pace_sent * 1000000 > (now_us() - pace_start) * SEND_RATE) {
            usleep(100);
        }

        total_bytes += send_chunk(m, i, seq, flags);
        pace_sent++;                                              
        if (flags & RETRANSMIT_FLAG) total_retransmits++;         
        else total_packets++;
    
    }


}