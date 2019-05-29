/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>

#include <rte_memory.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#include "common.h"
#include "args.h"
#include "init.h"

/* global var for number of clients - extern in header */
uint8_t num_clients;

static const char *progname;

/**
 * Prints out usage information to stdout
 */
static void
usage(void)
{
	printf(
	    "%s [EAL options] -- -p PORTMASK -n NUM_CLIENTS [-s NUM_SOCKETS]\n"
	    " -p PORTMASK: hexadecimal bitmask of ports to use\n"
	    " -n NUM_CLIENTS: number of client processes to use\n"
	    , progname);
}

/**
 * The ports to be used by the application are passed in
 * the form of a bitmask. This function parses the bitmask
 * and places the port numbers to be used into the port[]
 * array variable
 */
static int
parse_portmask(uint8_t max_ports, const char *portmask)
{
	char *end = NULL;
	unsigned long pm;
	uint16_t count;

	if (portmask == NULL || *portmask == '\0')
		return -1;

	/* convert parameter to a number and verify */
	pm = strtoul(portmask, &end, 16);
	if (end == NULL || *end != '\0' || pm > UINT16_MAX || pm == 0)
		return -1;

	/* loop through bits of the mask and mark ports */
	for (count = 0; pm != 0; pm >>= 1, ++count) {
		struct rte_eth_dev_owner owner;

		if ((pm & 0x1) == 0)
			continue;

		if (count >= max_ports) {
			printf("WARNING: requested port %u not present - ignoring\n",
				count);
			continue;
		}
		if (rte_eth_dev_owner_get(count, &owner) < 0) {
			printf("ERROR: can not find port %u owner\n", count);
			return -1;
		}
		if (owner.id != RTE_ETH_DEV_NO_OWNER) {
			printf("ERROR: requested port %u is owned by device %s\n",
					count, owner.name);
			return -1;
		}

		ports->id[ports->num_ports++] = count;
	}

	return 0;
}

/**
 * Take the number of clients parameter passed to the app
 * and convert to a number to store in the num_clients variable
 */
static int
parse_num_clients(const char *clients)
{
	char *end = NULL;
	unsigned long temp;

	if (clients == NULL || *clients == '\0')
		return -1;

	temp = strtoul(clients, &end, 10);
	if (end == NULL || *end != '\0' || temp == 0)
		return -1;

	num_clients = (uint8_t)temp;
	return 0;
}

/**
 * The application specific arguments follow the DPDK-specific
 * arguments which are stripped by the DPDK init. This function
 * processes these application arguments, printing usage info
 * on error.
 */
int
parse_app_args(uint16_t max_ports, int argc, char *argv[])
{
	int option_index, opt;
	char **argvopt = argv;
	static struct option lgopts[] = { /* no long options */
		{NULL, 0, 0, 0 }
	};
	progname = argv[0];

	while ((opt = getopt_long(argc, argvopt, "n:p:", lgopts,
		&option_index)) != EOF){
		switch (opt){
			case 'p':
				if (parse_portmask(max_ports, optarg) != 0){
					usage();
					return -1;
				}
				break;
			case 'n':
				if (parse_num_clients(optarg) != 0){
					usage();
					return -1;
				}
				break;
			default:
				printf("ERROR: Unknown option '%c'\n", opt);
				usage();
				return -1;
		}
	}

	if (ports->num_ports == 0 || num_clients == 0){
		usage();
		return -1;
	}

	if (ports->num_ports % 2 != 0){
		printf("ERROR: application requires an even number of ports to use\n");
		return -1;
	}
	return 0;
}
