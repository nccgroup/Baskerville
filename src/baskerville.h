/*
Selective protocol extractor from PCAPs or interfaces

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed for John Green, cirt at nccgroup dot com

https://github.com/nccgroup/baskerville

Released under AGPL see LICENSE for more information
*/


#define OPTION_SIZE 256

typedef struct option_t {
	char filter[OPTION_SIZE];
	char directory[OPTION_SIZE];
	long filesize;
	unsigned int limit;
	bool suppress[LPI_PROTO_LAST];
	bool verbose;
	bool help;
	bool quitting;
	} option_t;

/*
typedef struct packet_queue {
	libtrace_packet_t *packet;
	struct packet_queue  *next;
} packet_queue_t;
*/

typedef struct counter {
        uint64_t packets;
        uint8_t init_dir;
        uint64_t server_packets;
        uint64_t client_packets;
        void* server_data;
        void* client_data;
        uint64_t server_data_len;
        uint64_t client_data_len;
        lpi_data_t lpi_data;
	uint64_t server_packets_written;
	uint64_t client_packets_written;
} counterFlow_t;



