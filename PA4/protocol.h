#define __PROTOCOL_H__
#include <stdint.h>


#define SENDER_PORT 5000
#define RECEIEVR_PORT 5001
#define MCAST_GROUP "239.0.0.1"

// size limitation
// when we run the sender program, we use the -c to define the chunk size
#define DEFAULT_CHUNK_SIZE 1024 // when there no -c default 1024byte
#define MAX_CHUNK_SIZE 8192
#define MAX_NAME_LEN 128 // maximum file name
#define MAX_FILES 16// allow one file been splited into 16 files
#define MAX_NACK_RANGES 128 // allow 128 missing range to be sent (eg: 128-130, 140-145, ...)

// packet type 
// every packet has it's first 2byte to be magic number
#define PROTO_MAGIC 0x4D43 // represent the Multicast
#define RETRANSMIT_FLAG 0x01 // use the last bit of flag (at test receiver will 
// drop some 1st transmit packet, use it to distinguish retransmit pkt and 1st pkt)

enum packet_type {
    PACKET_ANNOUNCE = 1, // sender : description of one file
    PACKET_DATA=2,  // sener : this is one chunk of one file
    PACKET_NACK = 3 // receiver : i missing these chunks
};

// __attribute__((packed))不允许字节填充，防止两段编译器对不上
typedef struct __attribute__((packed)) {
    uint16_t magic; // 2 byte
    uint8_t type; // 1 byte
    uint8_t flags; // 1 byte
} pkt_header_t;

// ANNOUNCE packet 
typedef struct __attribute__((packed)) {
    pkt_header_t hdr; // the general header for all packet
    uint16_t file_id; // this is the ith file
    uint32_t num_files; // total number of files
    uint32_t file_size; // number of byte for this file
    uint32_t total_chunks; // number of chunks for this file
    uint32_t chunk_size;
    uint8_t  sha256[32]; // sender read file的时候算 sha256 放入ANNOUNCE对应字段，receiver收起所以chunk，拼好文件再算一遍，相同则文件没问题
    char name[MAX_NAME_LEN];
} pkt_announce_t;

// DATA packet
typedef struct __attribute__((packed)) 
{
    pkt_header_t hrd; // general header
    uint16_t file_id; // this is the ith file
    uint32_t seq; // sequence number of the packet (0 - total_chunk -1)
    uint32_t total_chunks;
    uint32_t checksum; // data checksum
    uint16_t data_len; // effective bytes in data[]
    uint8_t data[];
} pkt_data_t;

# define MAX_PACKET_SIZE (sizeof(pkt_data_t) + MAX_CHUNK_SIZE) // 24 + 8192 = 8216byte

// NACK packet (missing chunk request)
typedef struct __attribute__((packed)) {
    uint32_t start;
    uint32_t end; // the range of the seq of missing chunk
} nack_range_t;

// 
typedef struct __attribute__((packed))
{
    pkt_header_t hdr;
    uint32_t receiver_id; // which receiver send this NACK packet
    uint16_t file_id; // NACK at which file
    uint16_t num_ranges; // number of entries used by following array
    nack_range_t ranges[MAX_NACK_RANGES]; // at most 128 ranges been sent at same time
} pkt_nack_t;



