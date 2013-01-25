/*
udpmon - udp payload dump
Copyright (C) 2012 David Kierzokwski (kd8eyf@digitalham.info)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. */
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "/usr/include/pcap/pcap.h" 	// NEED TO FIX THIS
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<getopt.h>
#include<time.h>	
struct UDP_hdr {
        u_short	uh_sport;				//Source Port
        u_short	uh_dport;				//Destnation Port
        u_short	uh_ulen;				//Datagram Length
        u_short	uh_sum;					//Datagram Checksum
};
int debug = 0;
char *devname = NULL;
uint16_t SrcID = ((uint16_t)67 << 8) | ((uint16_t)65 << 0);
void usage( int8_t e );
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
	struct ip * ip;
        struct UDP_hdr * udp;
        unsigned int IP_header_length;
        unsigned int capture_len = pkthdr->len;
        int i=0, *counter = (int *)arg;
	time_t Time;	
	char* c_time_string;
	packet += sizeof (struct ether_header);
        capture_len -= sizeof(struct ether_header);
        ip = (struct ip*) packet;
        IP_header_length = ip->ip_hl *4;
        packet += IP_header_length;
        capture_len -= IP_header_length;
        udp = (struct UDP_hdr*) packet;
        packet += sizeof (struct UDP_hdr);
        capture_len -= sizeof (struct UDP_hdr);
 	Time = time(NULL);	
	c_time_string = time(&Time);
		printf("L:%3i ",capture_len);
                printf("T:%10ju ",(uintmax_t)Time);
		printf("S:%15s ",inet_ntoa(ip->ip_src));
		printf(":%5d ",ntohs(udp->uh_sport));
		printf("D:%15s", inet_ntoa(ip->ip_dst));			
	        printf(":%5d ",ntohs(udp->uh_dport));
		while (i < capture_len) {
                       printf("%02X", packet[i]);
                        i++;
               };
	printf("\n");
	fflush(stdout);
}
int main(int argc, char *argv[] )
{
	setbuf(stdout, NULL);
        char packet_filter[] ="udp";
        struct bpf_program fcode;
        u_int netmask;
        pcap_t *descr = NULL;
        int32_t c;
         while ((c = getopt(argc, argv, "Vhi:")) != EOF) {
                switch (c) {
                case 'V':
                        version();
                        break;
                case 'i':
                        devname = optarg;
                        break;
                case 'h':
                        usage(-1);
                        break;
                }
        }
	if (devname == NULL) {
                usage(-1);
        }
        if (debug == 1) {
                printf("USING CAPTURE DEVICE: %s\n", devname);
        }

        pcap_if_t *alldevsp , *device;
        pcap_t *handle;
        char errbuf[100] , devs[100][100];
        int count = 1 , n;
        handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
                exit(1);
        }
        pcap_compile(handle, &fcode, packet_filter, 1, netmask);

        if ( pcap_loop(handle, -1, processPacket, (u_char *)&count) == -1) {
                fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
                exit(1);
        }
        return 0;
}
void usage(int8_t e)
{
        printf(	"Usage: udpmon [OPTION]... \n"
                "Listen for udp packets and dump payload on screen\n"
                "\n"
		"   -i, --interface     Interface to listen on\n"
                "   -h, --help          This Help\n"
                "   -V, --version       Version Information\n"
                "   -d, --debug         Show verbose information\n"
                "\n"
                "Report bugs to kd8eyf@digitalham.info\n");
        exit(e);
}

int version ( void )
{
        printf ("udpmon 1.00\n");
        exit(1);
}












