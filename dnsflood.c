#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/wait.h>
#include <getopt.h>
#include <arpa/inet.h>

#define	CLASS_INET 1

enum dns_type {
    TYPE_A      = 1,
    TYPE_NS     = 2,
    TYPE_MD     = 3,
    TYPE_MF     = 4,
    TYPE_CNAME  = 5,
    TYPE_SOA    = 6,
    TYPE_MB     = 7,
    TYPE_MG     = 8,
    TYPE_MR     = 9,
    TYPE_NULL   = 10,
    TYPE_WKS    = 11,
    TYPE_PTR    = 12,
    TYPE_HINFO  = 13,
    TYPE_MINFO  = 14,
    TYPE_MX     = 15,
    TYPE_TXT    = 16,
    TYPE_AAAA   = 0x1c,
};

typedef struct type_name {
    uint16_t type;
    char typename[8];
} type_name_t;

type_name_t dns_type_names[] = {
    {TYPE_A, "A"},
    {TYPE_NS, "NS"},
    {TYPE_MD, "MD"},
    {TYPE_MF, "MF"},
    {TYPE_CNAME, "CNAME"},
    {TYPE_SOA, "SOA"},
    {TYPE_MB, "MB"},
    {TYPE_MG, "MG"},
    {TYPE_MR, "MR"},
    {TYPE_NULL, "NULL"},
    {TYPE_WKS, "WKS"},
    {TYPE_PTR, "PTR"},
    {TYPE_HINFO, "HINFO"},
    {TYPE_MINFO, "MINFO"},
    {TYPE_MX, "MX"},
    {TYPE_TXT, "TXT"},
    {TYPE_AAAA, "AAAA"},
};

#define DNS_TYPE_NUM (sizeof(dns_type_names) / sizeof(type_name_t))

struct dnshdr {
    unsigned short int id;

    unsigned char rd:1;         /* recursion desired */
    unsigned char tc:1;         /* truncated message */
    unsigned char aa:1;         /* authoritive answer */
    unsigned char opcode:4;     /* purpose of message */
    unsigned char qr:1;         /* response flag */

    unsigned char rcode:4;      /* response code */
    unsigned char unused:2;     /* unused bits */
    unsigned char pr:1;         /* primary server required (non standard) */
    unsigned char ra:1;         /* recursion available */

    unsigned short int que_num;
    unsigned short int rep_num;
    unsigned short int num_rr;
    unsigned short int num_rrsup;
};

uint16_t get_type(const char *type)
{
    int i;
    for (i = 0; i < DNS_TYPE_NUM; i++) {
        if (strcasecmp(type, dns_type_names[i].typename) == 0) {
            return dns_type_names[i].type;
        }
    }

    return 0;
}

unsigned short in_cksum(char *packet, int len)
{
    register int nleft = len;
    register u_short *w = (u_short *) packet;
    register int sum = 0;
    u_short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /*
     * mop up an odd byte, if necessary 
     */

    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

    /*
     * add back carry outs from top 16 bits to low 16 bits 
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

void usage(char *progname)
{
    printf("Usage: %s <query_name> <destination_ip> [options]\n"
           "\t<query_name>\t\tinput \"random\" to enable random query name\n"
           "\tOptions:\n"
           "\t-t, --type\t\tquery type\n"
           "\t-T, --target\t\ttarget domain name\n"
           "\t-s, --source-ip\t\tsource ip\n"
           "\t-p, --dest-port\t\tdestination port\n"
           "\t-P, --src-port\t\tsource port, default comply with RFC6056, '-1' - range 0~65535\n"
           "\t-i, --interval\t\tinterval (in millisecond) between two packets\n"
           "\t-n, --number\t\tnumber of DNS requests to send\n"
           "\t-r, --random\t\tfake random source IP\n"
           "\t-D, --daemon\t\trun as daemon\n"
           "\t-h, --help\n"
           "\n", progname);
}

/*
 * RFC 1035 - https://www.ietf.org/rfc/rfc1035.txt
 *
 * 2.3.1. Preferred name syntax
 * 
 * Note that while upper and lower case letters are allowed in domain
 * names, no significance is attached to the case.  That is, two names with
 * the same spelling but different case are to be treated as if identical.
 *
 * The labels must follow the rules for ARPANET host names.  They must
 * start with a letter, end with a letter or digit, and have as interior
 * characters only letters, digits, and hyphen.  There are also some
 * restrictions on the length.  Labels must be 63 characters or less.
 *
 * For example, the following strings identify hosts in the Internet:
 *
 * A.ISI.EDU XX.LCS.MIT.EDU SRI-NIC.ARPA
 *
 * 2.3.4. Size limits
 *
 * Various objects and parameters in the DNS have size limits.  They are
 * listed below.  Some could be easily changed, others are more
 * fundamental.
 *
 * labels          63 octets or less
 *
 * names           255 octets or less
 *
 * TTL             positive values of a signed 32 bit number.
 *
 * UDP messages    512 octets or less
 */

/*
 * Return a valid random label string
 */
char *randomLabel(size_t len, char *rLabel)
{
    const static char validChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
    size_t charsetLen = sizeof validChars - 1;
    size_t letterLen = sizeof validChars - 12;
    size_t letdigLen = sizeof validChars - 2;
    size_t n;

#ifdef DEBUG
    if (len > 63 || len < 1) {
        printf("Invalid label length: %d.\nLabels must be 63 characters or less.\n", (int)len);
        exit(1);
    }
#endif

    if (rLabel) {
        // They must start with a letter.
        rLabel[0] = validChars[random() % letterLen];
        // and have as interior characters only letters, digits, and hyphen.
        for (n = 1; n < (len - 1); n++) {
            rLabel[n] = validChars[random() % charsetLen];
        }
        // end with a letter or digit
        if (n < len)
            rLabel[n] = validChars[random() % letdigLen];

        rLabel[len] = '\0';

#ifdef DEBUG
        printf("Label: %02d %s\n", (int)strlen(rLabel), rLabel);
#endif

    }
    return rLabel;
}

void randomName(int len, int label_cnt, char *rName)
{
    int i;

    label_cnt += (random() % (len / 64 + 1)) + 1;
#ifdef DEBUG
    printf("LabelCnt: %d\n", label_cnt);
#endif
    for (i = 0; i < label_cnt && len > 1; i++) {
        if (len > 63)
            randomLabel((random() % 63) + 1, rName);
        else
            randomLabel((random() % len) + 1, rName);
        strcat(rName, ".");
        len -= strlen(rName);
        rName += strlen(rName);
    }
}

void randomAddr(char *addr)
{
    uint32_t rAddr = random();

    addr += snprintf(addr, 5, "%d.", (int)((rAddr >> 24 & 0xFD) + 1));
    addr += snprintf(addr, 5, "%d.", (int)(rAddr >> 16 & 0xFF));
    addr += snprintf(addr, 5, "%d.", (int)(rAddr >> 8 & 0xFF));
    snprintf(addr, 4, "%d", (int)((rAddr & 0xFD) + 1));
}

void nameformat(char *name, char *target)
{
    // max label length is 63, plus 1 byte of length, plus 1 byte '\0'
    char fullname[255];
    char *bungle = fullname;
    char *x = NULL;
    int cpLen;

    *target = 0;
    strcpy(bungle, name);
    x = strtok(bungle, ".");
    while (x != NULL) {
        cpLen = snprintf(target, 65, "%c%s", (int)strlen(x), x);
        if (cpLen >= 65) {
            puts("String overflow.");
#ifdef DEBUG
            printf("cpLen: %d, Len: %d, inStr: %s, cpStr: %s\n", cpLen, (int)strlen(x), x, target);
#endif
            exit(1);
        }
        target += cpLen;
        x = strtok(NULL, ".");
    }
}

void nameformatIP(char *ip, char *target)
{
    char *comps[8];
    char fullptr[32];
    char *pbungle = fullptr;
    char *x = NULL;
    char ina[] = "in-addr";
    char end[] = "arpa";
    int px = 0;
    int cpLen;

    *target = 0;
    strcpy(pbungle, ip);
    x = strtok(pbungle, ".");
    while (x != NULL) {
        if (px >= 4) {
            puts("Force DUMP:: dumbass, wtf you think this is, IPV6?");
            exit(1);
        }
        comps[px++] = x;
        x = strtok(NULL, ".");
    }

    for (px--; px >= 0; px--) {
        cpLen = snprintf(target, 5, "%c%s", (int)strlen(comps[px]), comps[px]);
        if (cpLen >= 5) {
            puts("Invalid IP Address.");
#ifdef DEBUG
            printf("cpLen: %d, Len: %d, inStr: %s, cpStr: %s\n", cpLen, (int)strlen(comps[px]), comps[px], target);
#endif
            exit(1);
        }
        target += cpLen;
    }

    target += snprintf(target, sizeof(ina) + 2, "%c%s", (int)strlen(ina), ina);
    snprintf(target, sizeof(end) + 2, "%c%s", (int)strlen(end), end);
}

int make_question_packet(char *data, char *name, int type)
{
    if(type == TYPE_PTR)
        nameformatIP(name, data);
    else
        nameformat(name, data);

    *((u_short *) (data + strlen(data) + 1)) = htons(type);

    *((u_short *) (data + strlen(data) + 3)) = htons(CLASS_INET);

    return (strlen(data) + 5);
}

int read_ip_from_file(char *filename)
{
    return 0;
}

void urandom_init() {
    unsigned long mySeed;
    unsigned long *buf = &mySeed;
    int urandom_fd = open("/dev/urandom", O_RDONLY);

    if (urandom_fd >= 0) {
        ssize_t result = read(urandom_fd, buf, sizeof(long));
        if (result < 0)
            mySeed = 0x4a6f6273;
    } else {
        mySeed = 0x4a6f6273;
    }
    srandom((unsigned long) time(NULL) * getpid() + mySeed);
}

int main(int argc, char **argv)
{
    char qname[256] = { 0 };    /* question name */
    char tarDN[256] = { 0 };    /* target domain */
    uint16_t qtype = TYPE_A;
    struct in_addr src_ip = { 0 };  /* source address */
    struct sockaddr_in sin_dst = { 0 }; /* destination sock address */
    u_short src_port = 0;       /* source port */
    u_short dst_port = 53;      /* destination port */
    int sock;                   /* socket to write on */
    int number = 0;
    int count = 0;
    int sleep_interval = 0;     /* interval (in millisecond) between two packets */

    int src_opt = -2;
    int randqname_opt = 0;      /* random query name option flag */
    int random_ip = 0;
    //int static_ip = 0;

    int arg_options;

    const char *short_options = "f:t:T:p:P:D:r:s:i:n:h";

    const struct option long_options[] = {
        {"type", required_argument, NULL, 't'},
        {"target", required_argument, NULL, 'T'},
        {"dest-port", required_argument, NULL, 'p'},
        {"file", required_argument, NULL, 'f'},
        {"src-port", required_argument, NULL, 'P'},
        {"daemon", no_argument, NULL, 'D'},
        {"random", no_argument, NULL, 'r'},
        {"source-ip", required_argument, NULL, 's'},
        {"interval", required_argument, NULL, 'i'},
        {"number", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int quit = 0;
    const int on = 1;

    //char *from, *to, filename;
    //int itmp = 0;

    unsigned char packet[1500] = { 0 };
    struct ip *iphdr;
    struct udphdr *udp;
    struct dnshdr *dns_header;
    char *dns_data;

    // Initial random seed
    urandom_init();

    while ((arg_options = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {

        switch (arg_options) {

        case 'p':
            dst_port = atoi(optarg);
            break;

        case 'P':
            src_opt = atoi(optarg);
            if (src_opt >= 0)
                src_port = src_opt;
            else if (src_opt < -1)
                src_opt = -2;
            break;

        case 'i':
            sleep_interval = atoi(optarg) * 1000;
            break;

        case 'n':
            number = atoi(optarg);
            break;

        case 'r':
            random_ip = 1;
            break;

        case 'D':
            // TODO
            break;

        case 'f':
            if (read_ip_from_file(optarg)) {
            }
            break;

        case 's':
            //static_ip = 1;
            inet_pton(AF_INET, optarg, &src_ip);
            break;

        case 't':
            qtype = get_type(optarg);
            if (qtype == 0) {
                printf("bad query type\n");
                quit = 1;
            }
            break;

        case 'T':
            if (snprintf(tarDN, sizeof(tarDN), "%s", optarg) >= 192) {
                printf("bad target domain\n");
                quit = 1;
            }
            printf("Target Domain: %s\n", tarDN);
            break;

        case 'h':
            usage(argv[0]);
            return 0;
            break;

        default:
            printf("CMD line Options Error\n\n");
            break;
        }
    }

    // query name 
    if (optind < argc) {
        snprintf(qname, sizeof(qname), "%s", argv[optind]);
        //strcpy(qname, argv[optind]);
        if (!strcmp(qname, "random"))
            randqname_opt = 1;
    } else {
        quit = 1;
    }

    optind++;

    // target IP 
    if (optind < argc) {
        inet_pton(AF_INET, argv[optind], &sin_dst.sin_addr);
    } else {
        quit = 1;
    }

    if (quit || !sin_dst.sin_addr.s_addr) {
        usage(argv[0]);
        exit(0);
    }

    // check root user 
    if (getuid() != 0) {
        printf("This program must run as root privilege.\n");
        exit(1);
    }

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        printf("\n%s\n", "Create RAW socket failed\n");
        exit(1);
    }

    if ((setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on))) == -1) {
        perror("setsockopt");
        exit(-1);
    }

    sin_dst.sin_family = AF_INET;
    sin_dst.sin_port = htons(dst_port);

    iphdr = (struct ip *) packet;
    udp = (struct udphdr *) ((char *) iphdr + sizeof(struct ip));
    dns_header = (struct dnshdr *) ((char *) udp + sizeof(struct udphdr));
    dns_data = (char *) ((char *) dns_header + sizeof(struct dnshdr));

    // the fixed fields for DNS header 
    dns_header->rd = 1;
    dns_header->que_num = htons(1);
    dns_header->qr = 0;         /* qr = 0: question packet */
    dns_header->aa = 0;         /* aa = 0: not auth answer */
    dns_header->rep_num = htons(0); /* sending no replies */

    // the fixed fields for UDP header 
    udp->uh_dport = htons(dst_port);
    if (src_opt >= 0) {
        udp->uh_sport = htons(src_port);
    }

    // the fixed fields for IP header 
    iphdr->ip_dst.s_addr = sin_dst.sin_addr.s_addr;
    iphdr->ip_v = IPVERSION;
    iphdr->ip_hl = sizeof(struct ip) >> 2;
    iphdr->ip_ttl = 245;
    iphdr->ip_p = IPPROTO_UDP;

    if (randqname_opt)
        printf("Sending Random DNS Query Request...\n");
    else
        printf("Sending DNS Request for querying %s.\n", qname);
    
    if (src_opt == -2)
        printf("Ephemeral Port Range: 1024~65535.\n");
    else if (src_opt == -1)
        printf("Ephemeral Port Range: 0~65535.\n");
    else if (src_opt >= 0)
        printf("Specific Ephemeral Port: %u.\n", src_port);

    while (1) {
        int dns_datalen;
        int udp_datalen;
        int ip_datalen;

        ssize_t ret;

        if (random_ip) {
            src_ip.s_addr = random();
        }

        dns_header->id = random();

        // Generate random query name 
        if (randqname_opt) {
            // reset qname to empty 
            memset(qname, '\0', sizeof(qname) - 1);
            if (qtype == TYPE_PTR)
                randomAddr(qname);
            else if (strlen(tarDN)) {
                randomName(255 - strlen(tarDN), 0, qname);
                strcat(qname, tarDN);
            } else
                randomName(random() % 255 + 1, 2, qname);
        }

#ifdef DEBUG
        printf("QNAME: %03d %s\n", (int)strlen(qname), qname);
#endif

        dns_datalen = make_question_packet(dns_data, qname, qtype);

        udp_datalen = sizeof(struct dnshdr) + dns_datalen;
        ip_datalen = sizeof(struct udphdr) + udp_datalen;

        // update UDP header 
        if (src_opt == -2) {
            // By default - Comply with RFC6056 - Ephemeral port should in range: 1024~65535 
            udp->uh_sport = htons((random() % (65536 - 1024)) + 1024);
        } else if (src_opt == -1) {
            // As you want, will set Ephemeral port range to 0~65535 
            udp->uh_sport = htons(random() % 65536);
        }

#ifdef DEBUG
        printf("Src_opt: %d,\tudp_sport: %u\n", src_opt, ntohs(udp->uh_sport));
#endif

        udp->uh_ulen = htons(sizeof(struct udphdr) + udp_datalen);
        udp->uh_sum = 0;

        // update IP header 
        iphdr->ip_src.s_addr = src_ip.s_addr;
        iphdr->ip_id = random();
        // iphdr->ip_len = htons(sizeof(struct ip) + ip_datalen);
        iphdr->ip_len = sizeof(struct ip) + ip_datalen;
        iphdr->ip_sum = 0;
        // iphdr->ip_sum = in_cksum((char *)iphdr, sizeof(struct ip));

        ret =
            sendto(sock, iphdr, sizeof(struct ip) + ip_datalen, 0, (struct sockaddr *) &sin_dst,
                   sizeof(struct sockaddr));
        if (ret == -1) {
            // perror("sendto error");
        }

        count++;

        if (number > 0 && count >= number) {
            // done
            break;
        }

        if (sleep_interval > 0) {
            usleep(sleep_interval);
        }
    }

    printf("sent %d DNS requests.\n", count);

    return 0;
}
