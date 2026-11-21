#ifndef __MULTICAST_H__
#define __MULTICAST_H__

#include <sys/types.h>
#include <sys/socket.h>  //Core socket functions and structures like sockaddr_in.
#include <netinet/in.h> 
#include <arpa/inet.h>  //Functions for converting IP addresses 
#include <sys/poll.h>  // : Used for non-blocking checks to see if data is waiting to be read. 

typedef struct _mcast_t
{
    struct sockaddr_in addr; // destination (multicast address)
    struct sockaddr_in my_addr; // local address
    unsigned int addrlen;
    unsigned int my_addrlen;
    int sock;
    struct ip_mreq mreq;  // A specific structure for joining multicast group
    struct pollfd fds[2]; //  used for poll() for not freezing the program while waiting for incoming data.
    int nfds;
} mcast_t;

mcast_t *multicast_init(char *mcast_addr, int sport, int rport);
int multicast_send(mcast_t *m, void *msg, int msglen); // send message to everyone subscribed in the multicast group
void multicast_setup_recv(mcast_t *m); // to join multicast group
int multicast_receive(mcast_t *m, void *buf, int bufsize);
int multicast_check_receive(mcast_t *m); // use poll to check if data is waiting
void multicast_destroy(mcast_t *m); // leave the group, close the socket and free memory
int multicast_check_receive_timeout(mcast_t *m, int timeout_ms);

#endif