/*
Selective protocol extractor from PCAPs or interfaces

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed for John Green, cirt at nccgroup dot com

https://github.com/nccgroup/baskerville

Released under AGPL see LICENSE for more information
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <libtrace.h>
#include <libflowmanager.h>
#include <libprotoident.h>
#include <assert.h>

#include "baskerville.h"



/* Global variables */
option_t option;
libtrace_out_t *output = NULL;
/* */

static void populateSuppress(char *suppressStr, bool * protocolArray)
{
	int i;
	char *tok;
	char *savedPtr;

	/*Reads comma seperated list of protocols and sets flag in array if present */

	for (tok = strtok_r(suppressStr, ",", &savedPtr); tok;
	     tok = strtok_r(NULL, ",", &savedPtr)) {

		for (i = 0; i < LPI_PROTO_LAST; i++) {

			if (!strcmp(tok, lpi_print((lpi_protocol_t) i))) {
				protocolArray[i] = true;
				/* Match so no point testing any more */
				break;
			}

		}
		if (i == LPI_PROTO_LAST) {
			fprintf(stderr, "Unrecognised protocol to suppress\n");
			exit(1);
		}

	} /* strtok */
}

static long bytesFromMultiplier(char *inString)
{
/* Returns the number of bytes in a number with suffix */
/* Supports K, M, G */
/* We work in powers of 2  (eg 1024 bytes in 1K) */

	long value = 0;
	long factor = 1;
	char *suffix;

	value = strtol(inString, &suffix, 10);

	if (suffix) {
		/* We have a suffix */

		switch (*suffix) {
		case 'G':
			factor = 1 << 30;
			break;
		case 'M':
			factor = 1 << 20;
			break;
		case 'K':
			factor = 1 << 10;
			break;
		default:
			/* Unknown suffix, ignore */
			break;
		}

	}

	return (value * factor);
}

static void initCounterFlow(Flow * f, uint8_t dir)
{
	/* Initialises the structure used to store data within flow */
	counterFlow_t *cflow = NULL;

	cflow = (counterFlow_t *) malloc(sizeof(counterFlow_t));
	cflow->init_dir = dir;
	cflow->packets = 0;
	cflow->server_packets = 0;
	cflow->client_packets = 0;
	cflow->server_data = NULL;
	cflow->client_data = NULL;
	cflow->server_data_len = 0;
	cflow->client_data_len = 0;

	/* Initialise protocol ident structure */
	lpi_init_data(&cflow->lpi_data);

	assert(f->extension == NULL);
	f->extension = cflow;
}

void expireCounterFlows(double ts, bool exp_flag)
{
	Flow *expired;

	/* Loop until libflowmanager has no more expired flows available 
	   All TCP flows get completed here - no special handling of FIN */

	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {

		counterFlow_t *cflow = (counterFlow_t *) expired->extension;

		/*TODO: We can write out argus style data here */
/*
      printf ("Expiring flow containing %d packets in total\n",
	      (int) cflow->packets);
      printf ("%d packets sent by client \n", (int) cflow->client_packets);
      printf ("%d packets sent by server \n", (int) cflow->server_packets);

      printf ("%d bytes sent by client \n", (int) cflow->client_data_len);
      printf ("%d bytes sent by server \n", (int) cflow->server_data_len);
*/

		/* Free our custom data structure */
		free(cflow);

		/* VERY IMPORTANT: release the Flow structure itself so
		 * that libflowmanager can now safely delete the flow */
		lfm_release_flow(expired);
	}
}

static void writePacket(libtrace_packet_t * packet)
{
	char outputfilename[OPTION_SIZE+32] = "";
	char timeStr[16];
	// static libtrace_out_t output;
	int bytesOut;
	static long bytesWritten = 0;

	/* Writes packet to file */

	/* Do we need to rotate the output file */
	if (output && bytesWritten >= option.filesize) {
		trace_destroy_output(output);
		output = NULL;
		bytesWritten = 0;
	}

	/* Open a new file in required */
	if (!output) {
		time_t packetTime = trace_get_seconds(packet);
		snprintf(timeStr, 15, "%ld", packetTime);

		strncat(outputfilename, option.directory, OPTION_SIZE);
		strcat(outputfilename, "/");
		strncat(outputfilename, timeStr, 16);
		strcat(outputfilename, ".pcap");

		if (option.verbose) printf("INFO: Creating file %s\n", outputfilename);

		output = trace_create_output(outputfilename);
		if (trace_is_err_output(output)) {
			trace_perror_output(output, "ERROR: ");
			fprintf(stderr, "ERROR: trace_is_err_output\n");
			exit(1);
		}
		if (trace_start_output(output)) {
			fprintf(stderr, "ERROR: Failed to open %s\n",
				outputfilename);
			exit(1);
		}
	}

	bytesOut = trace_write_packet(output, packet);

	/* Should returns bytes written but always returns 0 for pcap: output */
	if (bytesOut <= 0) {
		fprintf(stderr, "ERROR: Failed to write packet\n");
		fprintf(stderr,
			"INFO:  Try using pcapfile: rather than pcap:\n");
		exit(1);
	}

	bytesWritten += bytesOut;

}

static void perPacket(libtrace_packet_t * packet)
{
/* TODO deal with IP fragment */
/* TODO IPv6 */

	Flow *f;
	counterFlow_t *cflow = NULL;
	double ts;
	uint8_t dir;
	bool is_new = false;

	libtrace_ip_t *ip = NULL;
	uint16_t l3_type;
	lpi_module_t *module;


/* Only analyse IPv4 packets */
	ip = (libtrace_ip_t *) trace_get_layer3(packet, &l3_type, NULL);
	if (l3_type == 0x0800 && ip != NULL) {

/* Examine all flows and expire them if needed based on current packet time */
		ts = trace_get_seconds(packet);
		expireCounterFlows(ts, false);

/* Guess direction - consistent but perhaps suboptimal*/
		if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
			dir = 0;
		else
			dir = 1;

		/* Ignore packets where the IP addresses are the same - something is
		 * probably screwy and it's REALLY hard to determine direction */
		if (ip->ip_src.s_addr == ip->ip_dst.s_addr) {
			fprintf(stderr, "saddr and daddr the same which is unexpected\n");
			exit(1);
			return;
		}

		f = lfm_match_packet_to_flow(packet, dir, &is_new);
		if (f) {

			if (is_new) {
				printf("New flow\n");
				initCounterFlow(f, dir);
			}

			cflow = (counterFlow_t *) f->extension;

			lpi_update_data(packet, &cflow->lpi_data, dir);

			module = lpi_guess_protocol(&cflow->lpi_data);

			/* Update flow statistics */
			cflow->packets++;
			if (dir)
				cflow->client_packets++;
			else
				cflow->server_packets++;

			/* Suppress if written requested number of packets in both directions */
			if ((option.suppress[module->protocol])
			    && (cflow->client_packets_written >= option.limit)
			    && (cflow->server_packets_written >=
				option.limit)) {
				//printf("Skipping this packet\n");
				lfm_update_flow_expiry_timeout(f, ts);
				return;
			}

			/* Update counter of number of written packet */
			if (dir)
				cflow->client_packets_written++;
			else
				cflow->server_packets_written++;

			/* Tell libflowmanager to update the expiry time for this flow */
			lfm_update_flow_expiry_timeout(f, ts);

		}
	}

	/* Write out current packet */
	writePacket(packet);

	return;

}

static void printHelp()
{
	fprintf(stderr, "\
Usage: baskerville [OPTION]... [inURI]...\n\
Writes network capture to directory based on timestamp\n\
\n\
-h, --help		prints this help\n\
-v, --verbose		verbose\n\
-p, --pcapfilter	specific optional bpf filter\n\
-d, --directory		output directory for traffic (prefixed with pcapfile: or erf:)\n\
-f, --filesize 		file size in bytes (default 1G)\n\
-l, --limit		packet limit for protocols which are suppressed (default 10)\n\
-s, --suppress		comma separated list of protocols we want limited capture\n\
                        (eg HTTPS, OpenVPN).  See https://secure.wand.net.nz/trac/libprotoident/wiki/SupportedProtocols\n\
");
	exit(0);

}

static int parseOptions(int argc, char **argv, option_t * option)
{
	int c;
	char suppress[OPTION_SIZE];

	memset(option, 0, sizeof(option_t));

	/* Defaults */
	option->filesize = 1<<20;  /* 1GB */
	option->limit = 10;
	strcpy(option->directory, "pcapfile:out");
	/* */

	while (1) {
		static struct option long_options[] = {
			{"verbose", no_argument, 0, 'v'},
			{"help", no_argument, 0, 'h'},
			{"pcapfilter", required_argument, 0, 'p'},
			{"directory", required_argument, 0, 'd'},
			{"filesize", required_argument, 0, 'f'},
			{"limit", required_argument, 0, 'l'},
			{"suppress", required_argument, 0, 's'},
			{0, 0, 0, 0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "vhp:d:f:l:s:", long_options,
				&option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case 'v':
			option->verbose = 1;
			break;
		case 'p':
			strncpy(option->filter, optarg, OPTION_SIZE - 1);
			break;
		case 'd':
			strncpy(option->directory, optarg, OPTION_SIZE - 1);
			break;
		case 'f':
			option->filesize = bytesFromMultiplier(optarg);
			break;
		case 'l':
			option->limit = atoi(optarg);
			break;
		case 's':
			strncpy(suppress, optarg, OPTION_SIZE - 1);
			populateSuppress(suppress, option->suppress);
			break;
		case 'h':
		case '?':
			printHelp();
			break;
		default:
			abort();
		}
	}

	return optind;
}

static void
libtrace_cleanup(libtrace_t * trace, libtrace_packet_t * packet,
		 libtrace_filter_t * filter)
{

	if (trace) {
		trace_destroy(trace);
		trace = NULL;
	}

	if (packet) {
		trace_destroy_packet(packet);
		packet = NULL;
	}

	if (filter) {
		trace_destroy_filter(filter);
		filter = NULL;
	}

	if (output)
		trace_destroy_output(output);

}

int main(int argc, char **argv)
{

	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;
	libtrace_filter_t *filter = NULL;
	bool opt_true = true;
	bool opt_false = false;

	int remaining;
	int file;
	char *filename;

/* Init Protocol detection library */
	if (lpi_init_library() == -1) {
		fprintf(stderr, "ERROR: Failed to initialise lpi library\n");
		exit(1);
	}

	remaining = parseOptions(argc, argv, &option);

/* Everthing after options should be files or interfaces to read from */
	if (argc < remaining + 1) {
		printHelp();
	}

/* Set lfm_set_config_options here if required */
/* LFM_CONFIG_TCP_ANYSTART allows flows to start on any TCP packet */
	if (lfm_set_config_option(LFM_CONFIG_TCP_ANYSTART, &opt_true) == 0)
		exit(1);

/* Create the following once for all inputs to allow flow state to span pcaps*/
	packet = trace_create_packet();

	if (option.filter) {
		filter = trace_create_filter(option.filter);
		if (!filter) {
			fprintf(stderr, "ERROR: Failed to create filter %s\n",
				option.filter);
			libtrace_cleanup(trace, packet, filter);
			exit(1);
		}
	}

	for (file = remaining; file < argc; file++) {

		filename = argv[file];
		if (option.verbose)
			printf("INFO: Processing %s\n", filename);

		trace = trace_create(filename);

		if (filter) {
			if (trace_config(trace, TRACE_OPTION_FILTER, filter) ==
			    -1) {
				trace_perror(trace, "Configuring filter");
				libtrace_cleanup(trace, packet, filter);
				exit(1);
			}
		}

		if (trace_start(trace)) {
			fprintf(stderr, "ERROR: Problem parsing %s\n",
				filename);
			trace_perror(trace, "Starting trace");
			libtrace_cleanup(trace, packet, filter);
			exit(1);
		}

		while (trace_read_packet(trace, packet) > 0) {
			perPacket(packet);
		}

		trace_destroy(trace);
		trace = NULL;

	}

	libtrace_cleanup(trace, packet, filter);

	lpi_free_library();
	return (0);

}
