#include <stdio.h>     
#include <stdlib.h>     
#include <string.h>     
#include <errno.h>      
#include <sys/stat.h>   
#include <arpa/inet.h>  
#include "protocol.h"
#include "multicast.h"

// receiver收到的文件放在这个directory
#define OUT_DIR "received_files" // where the rebuilt files are saved
#define RECV_BUFFER_BYTES (8 * 1024 * 1024)


// Global state of the receiver
static rfile_t files[MAX_FILES];
static int numFiles = 0; // 0 until been announced by the 1st ANNOUNCE packet
static uint32_t session_id = 0; // session id we are following from sender side
static int have_session = 0; // 0 until receive the 1st one
// Statistics
static unsigned long stat_data = 0;  // num of DATA packets written to a file
static unsigned long stat_duplicate = 0;  // num of chunk we already had
static unsigned long stat_unknown   = 0;  // num of DATA pkt for a file not announced yet
static unsigned long stat_bad  = 0;  // num of packets with wrong sizes/values


typedef struct {
    int hasAnnounce;
    char name[MAX_NAME_LEN];
    uint32_t size;
    uint32_t total_chunks;
    uint32_t chunk_size;
    uint8_t sha256[32];
    FILE *fp; // use to write out
    uint8_t *receivedSeq; // receivedSeq[seq] == 1 means we received this seq
    uint32_t numReceived; // have received how many diff chunk
    int complete; // collect all chunk or not
} rfile_t



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
    memccpy(f->sha256, a->sha256, sizeof(f->sha256));

    // copy the name of file
    memccpy(f->name, a->name, MAX_NAME_LEN);
    f->name[MAX_NAME_LEN - 1] = '\0'; // make sure it end with '\0'

    char path[MAX_NAME_LEN + 32];
    snprintf(path, sizeof(path), "%s/%s", OUT_DIR, f->name); // write the path
    f->fp = fopen*(path, "wb+"); // // create (or empty) the file for writing
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

    printf("file %u/%u announced: %s, %u bytes, %u chunks of %u bytes\n",
           id, total, f->name, f->size, f->total_chunks, f->chunk_size);

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
    // receive duplicate data packet (seq:i)
    if (f->receivedSeq[seq]) {stat_duplicate++; return;}

    // todo checksum part
    long offset = (long) seq * f->chunk_size;
    fseek(f->fp, offset, SEEK_SET); // move the ptr to the start write position
    if (fwrite(d->data, 1, len, f->fp) != len) {
        perror("fwrite");
        exit(1);
    }

    // successfully write the seq: i packet into the disk
    f-> receivedSeq[seq] = 1;
    f-> numReceived++;
    stat_data++;

    if (f->numReceived == f->total_chunks) { // have received all the chunks
        f->complete = 1;
        fflush(f->fp); // ensure everything on disk
        printf("file %u complete: %s (%u chunks)\n",
               id, f->name, f->total_chunks);
    }

}

static int allDone(void) {
    if (numFiles == 0) return 0;      // no ANNOUNCE yet
    for (int i=0; i<numFiles; i++) {
        if (!files[i].complete) return 0;
    }
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); // print each line at once, even into a log file

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
    printf("receiver joined %s at port %d, waiting for files...\n", MCAST_GROUP, DATA_PORT);

    // receive until every file is complete
    uint8_t buf[MAX_PACKET_SIZE];

    while (!allDone()) {
        if (multicast_check_receive(m) <= 0) {
            continue;
        }
        int n = multicast_receive(m, buf, sizeof(buf)); // n is the size of packet

        // Every packet starts with general header
        if (n < (int) sizeof(pkt_header_t)) {
            stat_bad++; continue;
        }
        pkt_header_t *h = (pkt_header_t *) buf;
        if (ntohs(h->magic) != PROTO_MAGIC) continue; // this is not our packet

        uint32_t sid = ntohl(h->session_id);
        if (!have_session) {
            session_id = sid;
            have_session = 1;
            printf("Following session %08x\n", session_id);
        } else if (sid != session_id) {
            // not the session id we are waiting for
            continue;
        }

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

        printf("Receiving done: %d files, %lu chunks, %lu dup, %lu early, %lu bad\n",
       num_files, stat_data, stat_duplicate, stat_unknown, stat_bad);

        for (int i = 0; i < num_files; i++) {
            fclose(files[i].fp);
            free(files[i].have);
        }
        multicast_destroy(m);
        return 0;
    }
}