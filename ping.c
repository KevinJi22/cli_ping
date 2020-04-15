#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>           
#include <netdb.h>           
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>       
#include <netinet/in.h>      
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h> 

#define IP_BLANK 0
#define IP_V4 4
#define IP_V6 6

#define MIN_IP_HEADER_SIZE 20
#define MAX_IP_HEADER_SIZE 60
#define MAX_IP6_PSEUDO_HEADER_SIZE 40

#define PACKET_SIZE 64
#define ICMP_ECHO 8
#define ICMP6_ECHO 128
#define ICMP_ECHO_REPLY 0
#define ICMP6_ECHO_REPLY 129

#define REQUEST_TIMEOUT 1000000
#define REQUEST_INTERVAL 1

int pingloop = 1;

// IPv6 uses a pseudo header
struct ip6_pseudo_hdr {
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
    uint32_t ip6_plen;
    uint8_t ip6_zero[3];
    uint8_t ip6_nxt;
};

static uint16_t calculate_checksum(unsigned short *addr, size_t size) {
    int numLeft = size;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (numLeft > 1) {
        sum += *w++;
        numLeft -= 2;
    }

    if (numLeft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

static uint64_t get_time(void) {
    struct timeval now;
    return gettimeofday(&now, NULL) != 0
        ? 0
        : now.tv_sec * 1000000 + now.tv_usec;
}

void intHandler(int dummy) { 
    pingloop = 0;
} 

static void send_ping (int sockfd, struct addrinfo *addrinfo, const char *addrstr, int id) {
    int sent_count = 0, received_count = 0;

    while (pingloop) {
        struct icmp icmp_request = {0};
        int send_result;
        char recv_buf[MAX_IP_HEADER_SIZE + sizeof(struct icmp)];
        int packet_size, size;
        socklen_t addrlen;
        uint8_t ip_vhl, ip_header_size;
        struct icmp *icmp_response;
        uint64_t start_time, delay;
        uint16_t checksum, expected_checksum;

        if (sent_count == 0) {
            printf("Sending requests to %s\n", addrstr);
        }
        else {
            sleep(REQUEST_INTERVAL);
        }

        icmp_request.icmp_type = addrinfo->ai_family == AF_INET6 ? ICMP6_ECHO : ICMP_ECHO;
        icmp_request.icmp_code = 0;
        icmp_request.icmp_cksum = 0;
        icmp_request.icmp_id = htons(id);
        icmp_request.icmp_seq = htons(++sent_count);

        switch (addrinfo->ai_family) {
            case AF_INET:
                icmp_request.icmp_cksum = calculate_checksum((unsigned short *)&icmp_request, sizeof(icmp_request));
                break;
            case AF_INET6: {
                struct {
                    struct ip6_pseudo_hdr ip6_hdr;
                    struct icmp icmp;
                } data = {0};

                data.ip6_hdr.ip6_src.s6_addr[15] = 1;
                data.ip6_hdr.ip6_dst = ((struct sockaddr_in6 *)&addrinfo->ai_addr)->sin6_addr;
                data.ip6_hdr.ip6_plen = htonl((uint32_t)sizeof(struct icmp));
                data.ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
                data.icmp = icmp_request;

                icmp_request.icmp_cksum = calculate_checksum((unsigned short *)&data, sizeof(data));
                break;
            }
        }

        start_time = get_time();

        // send frame to socket
        send_result = sendto(sockfd,
                             (const char *)&icmp_request,
                             sizeof(icmp_request),
                             0,
                             addrinfo->ai_addr,
                             (int)addrinfo->ai_addrlen);
        if (send_result < 0) {
            printf("\n Packet sending failed! \n");
            exit(EXIT_FAILURE);
        }

        switch (addrinfo->ai_family) {
            case AF_INET:
                packet_size = (int)(MAX_IP_HEADER_SIZE + sizeof(struct icmp));
                break;
            case AF_INET6:
                packet_size = (int)sizeof(struct icmp);
                break;
        }

        // RECEIVE LOOP
        for (;;) {
            // compute rtt
            delay = get_time() - start_time;

            addrlen = (int)addrinfo->ai_addrlen;
            size = recvfrom(sockfd, recv_buf, packet_size, 0, addrinfo->ai_addr, &addrlen);
            if (size == 0) {
                printf("Connection closed\n");
                break;
            }
            if (size < 0) {
                if (errno == EAGAIN) {
                    if (delay > REQUEST_TIMEOUT) {
                        printf("Request timed out\n");
                        break;
                    } else {
                        /* No data available yet, try to receive again. */
                        continue;
                    }
                } else {
                    printf("\n Packet receive failed! \n");
                    break;
                }
            }

            switch (addrinfo->ai_family) {
                case AF_INET:
                    ip_vhl = *(uint8_t *)recv_buf;
                    ip_header_size = (ip_vhl & 0x0F) * 4;
                    break;
                case AF_INET6:
                    ip_header_size = 0;
                    break;
            }

            icmp_response = (struct icmp *)(recv_buf + ip_header_size);
            icmp_response->icmp_cksum = ntohs(icmp_response->icmp_cksum);
            icmp_response->icmp_id = ntohs(icmp_response->icmp_id);
            icmp_response->icmp_seq = ntohs(icmp_response->icmp_seq);

            // check for an IP ethernet frame carrying ICMP echo reply
            if (icmp_response->icmp_id == id && ((addrinfo->ai_family == AF_INET && icmp_response->icmp_type == ICMP_ECHO_REPLY) ||
                (addrinfo->ai_family == AF_INET6 && (icmp_response->icmp_type != ICMP6_ECHO || icmp_response->icmp_type != ICMP6_ECHO_REPLY)))) {
                break;
            }
        }

        if (size <= 0) {
            continue;
        }

        checksum = icmp_response->icmp_cksum;
        icmp_response->icmp_cksum = 0;

        switch (addrinfo->ai_family) {
            case AF_INET:
                expected_checksum = calculate_checksum((unsigned short *)icmp_response, sizeof(*icmp_response));
                break;
            case AF_INET6: {
                struct {
                    struct ip6_pseudo_hdr ip6_hdr;
                    struct icmp icmp;
                } data = {0};

                data.ip6_hdr.ip6_plen = htonl((uint32_t)sizeof(struct icmp));
                data.ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
                data.icmp = *icmp_response;

                expected_checksum = calculate_checksum((unsigned short *)&data, sizeof(data));
                break;
            }
        }
        received_count++;

        printf("%d bytes from %s, icmp_seq=%d, %d packets sent, "
                "%d packets received, %.2f%% packet loss, time=%.2f ms",
               PACKET_SIZE,
               addrstr,
               icmp_response->icmp_seq,
               sent_count,
               received_count,
               ((sent_count - received_count)/sent_count) * 100.0,
               delay / 1000.0);

        if (checksum != expected_checksum) {
            printf(" (incorrect checksum: %x != %x)\n", checksum, expected_checksum);
        } else {
            printf("\n");
        }
    }
}

int main(int argc, char **argv) {
    char *target_host = NULL;
    int ip_version = IP_BLANK;
    int i, gai_status, sockfd = -1;
    struct addrinfo addrinfo_hints;
    struct addrinfo *addrinfo_head = NULL;
    struct addrinfo *addrinfo = NULL;
    void *addr;
    char addrstr[INET6_ADDRSTRLEN];
    uint16_t id = (uint16_t)getpid(), seq;

    if (argc < 2) {
        printf("Usage: sudo %s [-4 (IPv4) or -6 (IPv6)] hostname/IP address\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-4") == 0) {
                ip_version = IP_V4;
            } else if (strcmp(argv[i], "-6") == 0) {
                ip_version = IP_V6;
            }
        } else {
            target_host = argv[i];
        }
    }

    if (ip_version == IP_V4 || ip_version == IP_BLANK) {
        memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
        addrinfo_hints.ai_family = AF_INET;
        addrinfo_hints.ai_socktype = SOCK_RAW;
        addrinfo_hints.ai_protocol = IPPROTO_ICMP;
        gai_status = getaddrinfo(target_host, NULL, &addrinfo_hints, &addrinfo_head);
    } else {
        memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
        addrinfo_hints.ai_family = AF_INET6;
        addrinfo_hints.ai_socktype = SOCK_RAW;
        addrinfo_hints.ai_protocol = IPPROTO_ICMPV6;
        gai_status = getaddrinfo(target_host, NULL, &addrinfo_hints, &addrinfo_head);
    }

    if (gai_status != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(gai_status));
        exit(EXIT_FAILURE);
    }

    // addrinfo is a linked list
    for (addrinfo = addrinfo_head; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
        sockfd = socket(addrinfo->ai_family,
                        addrinfo->ai_socktype,
                        addrinfo->ai_protocol);
        if (sockfd >= 0) {
            // break when we get a socket
            break;
        }
    }

    // never got a valid socket
    if (sockfd < 0) {
        printf("socket error");
        exit(EXIT_FAILURE);
    }

    switch (addrinfo->ai_family) {
        case AF_INET:
            addr = &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            addr = &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr;
            break;
    }

    // Extract source IP address from received ethernet frame.
        if (inet_ntop(addrinfo->ai_family, addr, addrstr, sizeof(addrstr)) == NULL) {
          fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (errno));
          exit (EXIT_FAILURE);
        }
    

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        printf("fcntl error");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, intHandler);

    send_ping(sockfd, addrinfo, addrstr, id);

    return EXIT_SUCCESS;
}
