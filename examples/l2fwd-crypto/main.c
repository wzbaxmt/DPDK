/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2015-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_hexdump.h>

#include "main.h"
#include "socket.h"

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint64_t total_packets_enqueued, total_packets_dequeued,
		total_packets_errors;
	unsigned portid;
	uint64_t cdevid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
	total_packets_enqueued = 0;
	total_packets_dequeued = 0;
	total_packets_errors = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %32"PRIu64
			   "\nPackets received: %28"PRIu64
			   "\nPackets dropped: %29"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nCrypto statistics ==================================");

	for (cdevid = 0; cdevid < RTE_CRYPTO_MAX_DEVS; cdevid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_crypto_mask & (((uint64_t)1) << cdevid)) == 0)
			continue;
		printf("\nStatistics for cryptodev %"PRIu64
				" -------------------------"
			   "\nPackets enqueued: %28"PRIu64
			   "\nPackets dequeued: %28"PRIu64
			   "\nPackets errors: %30"PRIu64,
			   cdevid,
			   crypto_statistics[cdevid].enqueued,
			   crypto_statistics[cdevid].dequeued,
			   crypto_statistics[cdevid].errors);

		total_packets_enqueued += crypto_statistics[cdevid].enqueued;
		total_packets_dequeued += crypto_statistics[cdevid].dequeued;
		total_packets_errors += crypto_statistics[cdevid].errors;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets received: %22"PRIu64
		   "\nTotal packets enqueued: %22"PRIu64
		   "\nTotal packets dequeued: %22"PRIu64
		   "\nTotal packets sent: %26"PRIu64
		   "\nTotal packets dropped: %23"PRIu64
		   "\nTotal packets crypto errors: %17"PRIu64,
		   total_packets_rx,
		   total_packets_enqueued,
		   total_packets_dequeued,
		   total_packets_tx,
		   total_packets_dropped,
		   total_packets_errors);
	printf("\n====================================================\n");
}
//将待加密的报文数据发送给加密设备
static int
l2fwd_crypto_send_burst(struct lcore_queue_conf *qconf, unsigned n,
		struct l2fwd_crypto_params *cparams)
{
	struct rte_crypto_op **op_buffer;
	unsigned ret;

	op_buffer = (struct rte_crypto_op **)
			qconf->op_buf[cparams->dev_id].buffer;

	ret = rte_cryptodev_enqueue_burst(cparams->dev_id,
			cparams->qp_id,	op_buffer, (uint16_t) n);

	crypto_statistics[cparams->dev_id].enqueued += ret;
	if (unlikely(ret < n)) {
		crypto_statistics[cparams->dev_id].errors += (n - ret);
		do {
			rte_pktmbuf_free(op_buffer[ret]->sym->m_src);
			rte_crypto_op_free(op_buffer[ret]);
		} while (++ret < n);
	}

	return 0;
}

static int
l2fwd_crypto_enqueue(struct rte_crypto_op *op,
		struct l2fwd_crypto_params *cparams)
{
	unsigned lcore_id, len;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();

	qconf = &lcore_queue_conf[lcore_id];
	len = qconf->op_buf[cparams->dev_id].len;
	qconf->op_buf[cparams->dev_id].buffer[len] = op;
	len++;

	/* enough ops to be sent */
	if (len == MAX_PKT_BURST) 
	{
		l2fwd_crypto_send_burst(qconf, MAX_PKT_BURST, cparams);
		len = 0;
	}

	qconf->op_buf[cparams->dev_id].len = len;
	return 0;
}
//将从网口获取的数据包放入加密设备队列
static int
l2fwd_simple_crypto_enqueue(struct rte_mbuf *m, struct rte_crypto_op *op, struct l2fwd_crypto_params *cparams)
{
	struct ether_hdr *eth_hdr;/* 二层头 */
	struct ipv4_hdr *ip_hdr; /* IPv4头部 */

	uint32_t ipdata_offset, data_len;
	uint32_t pad_len = 0;/* 填充数据长度 */
	char *padding;		/* 填充的数据内容 */

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	if (eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))//只转发IPV4报文
		return -1;

	ipdata_offset = sizeof(struct ether_hdr);/* 二层头长度 */

	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) +
			ipdata_offset);

	ipdata_offset += (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK)
			* IPV4_IHL_MULTIPLIER;/* ip头部长度 */


	/* Zero pad data to be crypto'd so it is block aligned 
			数据长度 = 包m的长度-二层头的长度-ip头部长度*/
	data_len  = rte_pktmbuf_data_len(m) - ipdata_offset;

	if (cparams->do_hash && cparams->hash_verify)
		data_len -= cparams->digest_length;/* 如果有做认证，则减去hash摘要长度 */
	//加密，增加pad_len字节0
	if (cparams->do_cipher)
	{
		/*
		 * Following algorithms are block cipher algorithms,
		 * and might need padding 分组加密算法，可能需要填充数据
		 */
		switch (cparams->cipher_algo) 
		{
		case RTE_CRYPTO_CIPHER_AES_CBC:
		case RTE_CRYPTO_CIPHER_AES_ECB:
		case RTE_CRYPTO_CIPHER_DES_CBC:
		case RTE_CRYPTO_CIPHER_3DES_CBC:
		case RTE_CRYPTO_CIPHER_3DES_ECB:
			if (data_len % cparams->block_size)/* 如果数据长度模分组大小不为0 */
				pad_len = cparams->block_size -
					(data_len % cparams->block_size);/* 则计算填充数据长度 */
			break;
		default:
			pad_len = 0;
		}
		/* 如果需要填充 */
		if (pad_len) 
		{
			padding = rte_pktmbuf_append(m, pad_len);/* 将填充数据附加到m，并返回填充的数据首地址 */
			if (unlikely(!padding))
				return -1;

			data_len += pad_len;
			memset(padding, 0, pad_len);/* 将填充数据初始化为0 */
		}
	}
	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(op, cparams->session);
	/* 填充rte_crypto_op结构体的认证参数 */
	if (cparams->do_hash) 
	{
		if (cparams->auth_iv.length) {
			uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op,
						uint8_t *,
						IV_OFFSET +
						cparams->cipher_iv.length);
			/*
			 * Copy IV at the end of the crypto operation,
			 * after the cipher IV, if added
			 */
			rte_memcpy(iv_ptr, cparams->auth_iv.data,
					cparams->auth_iv.length);
		}
		if (!cparams->hash_verify) {
			/* Append space for digest to end of packet 将认证数据附加到数据包后面*/
			op->sym->auth.digest.data = (uint8_t *)rte_pktmbuf_append(m,
				cparams->digest_length);
		} else {
			op->sym->auth.digest.data = rte_pktmbuf_mtod(m,
				uint8_t *) + ipdata_offset + data_len;
		}

		op->sym->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(m,
				rte_pktmbuf_pkt_len(m) - cparams->digest_length);

		/* For wireless algorithms, offset/length must be in bits */
		if (cparams->auth_algo == RTE_CRYPTO_AUTH_SNOW3G_UIA2 ||
				cparams->auth_algo == RTE_CRYPTO_AUTH_KASUMI_F9 ||
				cparams->auth_algo == RTE_CRYPTO_AUTH_ZUC_EIA3) {
			op->sym->auth.data.offset = ipdata_offset << 3;
			op->sym->auth.data.length = data_len << 3;
		} else {
			op->sym->auth.data.offset = ipdata_offset;
			op->sym->auth.data.length = data_len;
		}
	}
	/* 填充rte_crypto_op结构体的加密参数 */
	if (cparams->do_cipher) 
	{
		uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *,
							IV_OFFSET);
		/* Copy IV at the end of the crypto operation */
		rte_memcpy(iv_ptr, cparams->cipher_iv.data,
				cparams->cipher_iv.length);

		/* For wireless algorithms, offset/length must be in bits */
		if (cparams->cipher_algo == RTE_CRYPTO_CIPHER_SNOW3G_UEA2 ||
				cparams->cipher_algo == RTE_CRYPTO_CIPHER_KASUMI_F8 ||
				cparams->cipher_algo == RTE_CRYPTO_CIPHER_ZUC_EEA3) {
			op->sym->cipher.data.offset = ipdata_offset << 3;
			op->sym->cipher.data.length = data_len << 3;
		} 
		else 
		{
			op->sym->cipher.data.offset = ipdata_offset;
			op->sym->cipher.data.length = data_len;
		}
	}

	if (cparams->do_aead) 
	{
		uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *,
							IV_OFFSET);
		/* Copy IV at the end of the crypto operation */
		rte_memcpy(iv_ptr, cparams->aead_iv.data, cparams->aead_iv.length);

		op->sym->aead.data.offset = ipdata_offset;
		op->sym->aead.data.length = data_len;

		if (!cparams->hash_verify) {
			/* Append space for digest to end of packet */
			op->sym->aead.digest.data = (uint8_t *)rte_pktmbuf_append(m,
				cparams->digest_length);
		} else {
			op->sym->aead.digest.data = rte_pktmbuf_mtod(m,
				uint8_t *) + ipdata_offset + data_len;
		}

		op->sym->aead.digest.phys_addr = rte_pktmbuf_mtophys_offset(m,
				rte_pktmbuf_pkt_len(m) - cparams->digest_length);

		if (cparams->aad.length) {
			op->sym->aead.aad.data = cparams->aad.data;
			op->sym->aead.aad.phys_addr = cparams->aad.phys_addr;
		}
	}
	/* m_src表示源数据，即没有加密之前的数据 */
	op->sym->m_src = m; //加密前的数据

	return l2fwd_crypto_enqueue(op, cparams);
}


/* Send the burst of packets on an output interface */
static int
l2fwd_send_burst(struct lcore_queue_conf *qconf, unsigned n,
		uint8_t port)
{
	struct rte_mbuf **pkt_buffer;
	unsigned ret;

	pkt_buffer = (struct rte_mbuf **)qconf->pkt_buf[port].buffer;

	ret = rte_eth_tx_burst(port, 0, pkt_buffer, (uint16_t)n);
	port_statistics[port].tx += ret;
	if (unlikely(ret < n)) {
		port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(pkt_buffer[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
static int
l2fwd_send_packet(struct rte_mbuf *m, uint8_t port)
{
	unsigned lcore_id, len;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();

	qconf = &lcore_queue_conf[lcore_id];
	len = qconf->pkt_buf[port].len;
	qconf->pkt_buf[port].buffer[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		l2fwd_send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->pkt_buf[port].len = len;
	return 0;
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned int dest_portid)
{
	struct ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned int portid,
		struct l2fwd_crypto_options *options)
{
	unsigned int dst_port;

	dst_port = l2fwd_dst_ports[portid];

	if (options->mac_updating)
		l2fwd_mac_updating(m, dst_port);

	l2fwd_send_packet(m, (uint8_t) dst_port);
}

/** Generate random key */
static void
generate_random_key(uint8_t *key, unsigned length)
{
	int fd;
	int ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		rte_exit(EXIT_FAILURE, "Failed to generate random key\n");

	ret = read(fd, key, length);
	close(fd);

	if (ret != (signed)length)
		rte_exit(EXIT_FAILURE, "Failed to generate random key\n");
}

static struct rte_cryptodev_sym_session *
initialize_crypto_session(struct l2fwd_crypto_options *options, uint8_t cdev_id)
{
	struct rte_crypto_sym_xform *first_xform;
	struct rte_cryptodev_sym_session *session;
	int retval = rte_cryptodev_socket_id(cdev_id);

	if (retval < 0)
		return NULL;

	uint8_t socket_id = (uint8_t) retval;
	struct rte_mempool *sess_mp = session_pool_socket[socket_id];

	if (options->xform_chain == L2FWD_CRYPTO_AEAD) {
		first_xform = &options->aead_xform;
	} else if (options->xform_chain == L2FWD_CRYPTO_CIPHER_HASH) {
		first_xform = &options->cipher_xform;
		first_xform->next = &options->auth_xform;
	} else if (options->xform_chain == L2FWD_CRYPTO_HASH_CIPHER) {
		first_xform = &options->auth_xform;
		first_xform->next = &options->cipher_xform;
	} else if (options->xform_chain == L2FWD_CRYPTO_CIPHER_ONLY) {
		first_xform = &options->cipher_xform;
	} else {
		first_xform = &options->auth_xform;
	}

	session = rte_cryptodev_sym_session_create(sess_mp);

	if (session == NULL)
		return NULL;

	if (rte_cryptodev_sym_session_init(cdev_id, session,
				first_xform, sess_mp) < 0)
		return NULL;

	return session;
}

static void
l2fwd_crypto_options_print(struct l2fwd_crypto_options *options);
//每一个逻辑核处理一个网口设备和一个crypto device
/* main processing loop */
static void
l2fwd_main_loop(struct l2fwd_crypto_options *options)
{
	struct rte_mbuf *m, *pkts_burst[MAX_PKT_BURST];
	struct rte_crypto_op *ops_burst[MAX_PKT_BURST];

	unsigned lcore_id = rte_lcore_id();//当前内核编号
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	unsigned i, j, portid, nb_rx, len;
	struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;
	struct l2fwd_crypto_params *cparams;
	struct l2fwd_crypto_params port_cparams[qconf->nb_crypto_devs];
	struct rte_cryptodev_sym_session *session;

	if (qconf->nb_rx_ports == 0) 
	{
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->nb_rx_ports; i++) 
	{
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	for (i = 0; i < qconf->nb_crypto_devs; i++) 
	{
		port_cparams[i].do_cipher = 0;
		port_cparams[i].do_hash = 0;
		port_cparams[i].do_aead = 0;

		switch (options->xform_chain) 
		{
		case L2FWD_CRYPTO_AEAD:
			port_cparams[i].do_aead = 1;
			break;
		case L2FWD_CRYPTO_CIPHER_HASH:
		case L2FWD_CRYPTO_HASH_CIPHER:
			port_cparams[i].do_cipher = 1;
			port_cparams[i].do_hash = 1;
			break;
		case L2FWD_CRYPTO_HASH_ONLY:
			port_cparams[i].do_hash = 1;
			break;
		case L2FWD_CRYPTO_CIPHER_ONLY:
			port_cparams[i].do_cipher = 1;
			break;
		}

		port_cparams[i].dev_id = qconf->cryptodev_list[i];
		port_cparams[i].qp_id = 0;

		port_cparams[i].block_size = options->block_size;

		if (port_cparams[i].do_hash) 
		{
			port_cparams[i].auth_iv.data = options->auth_iv.data;
			port_cparams[i].auth_iv.length = options->auth_iv.length;
			if (!options->auth_iv_param)
				generate_random_key(port_cparams[i].auth_iv.data,
						port_cparams[i].auth_iv.length);
			if (options->auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY)
				port_cparams[i].hash_verify = 1;
			else
				port_cparams[i].hash_verify = 0;

			port_cparams[i].auth_algo = options->auth_xform.auth.algo;
			port_cparams[i].digest_length =
					options->auth_xform.auth.digest_length;
			/* Set IV parameters */
			if (options->auth_iv.length) 
			{
				options->auth_xform.auth.iv.offset =
					IV_OFFSET + options->cipher_iv.length;
				options->auth_xform.auth.iv.length =
					options->auth_iv.length;
			}
		}

		if (port_cparams[i].do_aead) {
			port_cparams[i].aead_iv.data = options->aead_iv.data;
			port_cparams[i].aead_iv.length = options->aead_iv.length;
			if (!options->aead_iv_param)
				generate_random_key(port_cparams[i].aead_iv.data,
						port_cparams[i].aead_iv.length);
			port_cparams[i].aead_algo = options->aead_xform.aead.algo;
			port_cparams[i].digest_length =
					options->aead_xform.aead.digest_length;
			if (options->aead_xform.aead.aad_length) {
				port_cparams[i].aad.data = options->aad.data;
				port_cparams[i].aad.phys_addr = options->aad.phys_addr;
				port_cparams[i].aad.length = options->aad.length;
				if (!options->aad_param)
					generate_random_key(port_cparams[i].aad.data,
						port_cparams[i].aad.length);

			} else
				port_cparams[i].aad.length = 0;

			if (options->aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_DECRYPT)
				port_cparams[i].hash_verify = 1;
			else
				port_cparams[i].hash_verify = 0;

			/* Set IV parameters */
			options->aead_xform.aead.iv.offset = IV_OFFSET;
			options->aead_xform.aead.iv.length = options->aead_iv.length;
		}

		if (port_cparams[i].do_cipher) 
		{
			port_cparams[i].cipher_iv.data = options->cipher_iv.data;
			port_cparams[i].cipher_iv.length = options->cipher_iv.length;
			if (!options->cipher_iv_param)
				generate_random_key(port_cparams[i].cipher_iv.data,
						port_cparams[i].cipher_iv.length);

			//port_cparams[i].cipher_algo = options->cipher_xform.cipher.algo;
			// add enc or dec
			//port_cparams[i].cipher_op = options->cipher_xform.cipher.op;
			/* Set IV parameters */
			options->cipher_xform.cipher.iv.offset = IV_OFFSET;
			options->cipher_xform.cipher.iv.length =
						options->cipher_iv.length;
		}

		session = initialize_crypto_session(options,
				port_cparams[i].dev_id);
		if (session == NULL)
			rte_exit(EXIT_FAILURE, "Failed to initialize crypto session\n");

		port_cparams[i].session = session;

		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u cryptoid=%u\n", lcore_id,
				port_cparams[i].dev_id);
	}

	l2fwd_crypto_options_print(options);

	/*
	 * Initialize previous tsc timestamp before the loop,
	 * to avoid showing the port statistics immediately,
	 * so user can see the crypto information.
	 */
	prev_tsc = rte_rdtsc();
	while (1) 
	{
		cur_tsc = rte_rdtsc();

		/*
		 * Crypto device/TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
		{
			/* Enqueue all crypto ops remaining in buffers */
			for (i = 0; i < qconf->nb_crypto_devs; i++) 
			{
				cparams = &port_cparams[i];
				len = qconf->op_buf[cparams->dev_id].len;
				l2fwd_crypto_send_burst(qconf, len, cparams);
				qconf->op_buf[cparams->dev_id].len = 0;
			}
			/* Transmit all packets remaining in buffers */
			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) 
			{
				if (qconf->pkt_buf[portid].len == 0)
					continue;
				l2fwd_send_burst(&lcore_queue_conf[lcore_id],
						 qconf->pkt_buf[portid].len,(uint8_t) portid);
				qconf->pkt_buf[portid].len = 0;
			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >=
						(uint64_t)timer_period)) {

					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()
						&& options->refresh_period) {
						print_stats();
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->nb_rx_ports; i++) 
		{
			portid = qconf->rx_port_list[i];

			cparams = &port_cparams[i];
			/* 接收数据包，存储在pkts_burst数组中，一次可能接收多个数据rte_mbuf，
            返回值nb_rx为接收的数量 */
			nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			port_statistics[portid].rx += nb_rx;

			if (nb_rx) 
			{
				/*
				 * If we can't allocate a crypto_ops, then drop
				 * the rest of the burst and dequeue and
				 * process the packets to free offload structs
				 * 对于n个数据包，创建n个crypto operations
				 */
				if (rte_crypto_op_bulk_alloc(
						l2fwd_crypto_op_pool,
						RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						ops_burst, nb_rx) !=
								nb_rx) 
				{
					for (j = 0; j < nb_rx; j++)
						rte_pktmbuf_free(pkts_burst[j]);

					nb_rx = 0;
				}

				/* Enqueue packets from Crypto device 向加密设备中写入报文*/
				for (j = 0; j < nb_rx; j++) 
				{
					m = pkts_burst[j];
					/* 将数据包放入加密设备队列 */
					l2fwd_simple_crypto_enqueue(m,ops_burst[j], cparams);
				}
			}

			/* Dequeue packets from Crypto device 从加密设备中取出报文*/
			do 
			{
				nb_rx = rte_cryptodev_dequeue_burst(cparams->dev_id, cparams->qp_id, ops_burst, MAX_PKT_BURST);

				crypto_statistics[cparams->dev_id].dequeued += nb_rx;

				/* Forward crypto'd packets */
				for (j = 0; j < nb_rx; j++) 
				{
					m = ops_burst[j]->sym->m_src;
					//wyq
					{
						struct ipv4_hdr *ip_hdr; /* IPv4头部 */
						uint32_t ipdata_offset, data_len;
						uint32_t pad_len = 0;/* 填充数据长度 */
						
						ipdata_offset = sizeof(struct ether_hdr);/* 二层头长度 */
						ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset);
						data_len  = rte_pktmbuf_data_len(m) - ipdata_offset;
						
						if (!(data_len % cparams->block_size))/* 如果数据长度模分组大小是block_size整数倍 */
							pad_len = data_len - ip_hdr->total_length;/* 填充数据长度= 填充后的数据 - ip报文数据*/

						rte_pktmbuf_delete(m, pad_len);
					}
					
					rte_crypto_op_free(ops_burst[j]);
					l2fwd_simple_forward(m, portid,
							options);
				}
			} while (nb_rx == MAX_PKT_BURST);
		}
	}
}

static int
l2fwd_launch_one_lcore(void *arg)
{
	l2fwd_main_loop((struct l2fwd_crypto_options *)arg);
	return 0;
}

/* Display command line arguments usage */
static void
l2fwd_crypto_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		"  -s manage all ports from single lcore\n"
		"  -T PERIOD: statistics will be refreshed each PERIOD seconds"
		" (0 to disable, 10 default, 86400 maximum)\n"

		"  --cdev_type HW / SW / ANY\n"
		"  --chain HASH_CIPHER / CIPHER_HASH / CIPHER_ONLY /"
		" HASH_ONLY / AEAD\n"

		"  --cipher_algo ALGO\n"
		"  --cipher_op ENCRYPT / DECRYPT\n"
		"  --cipher_key KEY (bytes separated with \":\")\n"
		"  --cipher_key_random_size SIZE: size of cipher key when generated randomly\n"
		"  --cipher_iv IV (bytes separated with \":\")\n"
		"  --cipher_iv_random_size SIZE: size of cipher IV when generated randomly\n"

		"  --auth_algo ALGO\n"
		"  --auth_op GENERATE / VERIFY\n"
		"  --auth_key KEY (bytes separated with \":\")\n"
		"  --auth_key_random_size SIZE: size of auth key when generated randomly\n"
		"  --auth_iv IV (bytes separated with \":\")\n"
		"  --auth_iv_random_size SIZE: size of auth IV when generated randomly\n"

		"  --aead_algo ALGO\n"
		"  --aead_op ENCRYPT / DECRYPT\n"
		"  --aead_key KEY (bytes separated with \":\")\n"
		"  --aead_key_random_size SIZE: size of AEAD key when generated randomly\n"
		"  --aead_iv IV (bytes separated with \":\")\n"
		"  --aead_iv_random_size SIZE: size of AEAD IV when generated randomly\n"
		"  --aad AAD (bytes separated with \":\")\n"
		"  --aad_random_size SIZE: size of AAD when generated randomly\n"

		"  --digest_size SIZE: size of digest to be generated/verified\n"

		"  --sessionless\n"
		"  --cryptodev_mask MASK: hexadecimal bitmask of crypto devices to configure\n"

		"  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
		"      When enabled:\n"
		"       - The source MAC address is replaced by the TX port MAC address\n"
		"       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n",
	       prgname);
}

/** Parse crypto device type command line argument */
static int
parse_cryptodev_type(enum cdev_type *type, char *optarg)
{
	if (strcmp("HW", optarg) == 0) {
		*type = CDEV_TYPE_HW;
		return 0;
	} else if (strcmp("SW", optarg) == 0) {
		*type = CDEV_TYPE_SW;
		return 0;
	} else if (strcmp("ANY", optarg) == 0) {
		*type = CDEV_TYPE_ANY;
		return 0;
	}

	return -1;
}

/** Parse crypto chain xform command line argument */
static int
parse_crypto_opt_chain(struct l2fwd_crypto_options *options, char *optarg)
{
	if (strcmp("CIPHER_HASH", optarg) == 0) {
		options->xform_chain = L2FWD_CRYPTO_CIPHER_HASH;
		return 0;
	} else if (strcmp("HASH_CIPHER", optarg) == 0) {
		options->xform_chain = L2FWD_CRYPTO_HASH_CIPHER;
		return 0;
	} else if (strcmp("CIPHER_ONLY", optarg) == 0) {
		options->xform_chain = L2FWD_CRYPTO_CIPHER_ONLY;
		return 0;
	} else if (strcmp("HASH_ONLY", optarg) == 0) {
		options->xform_chain = L2FWD_CRYPTO_HASH_ONLY;
		return 0;
	} else if (strcmp("AEAD", optarg) == 0) {
		options->xform_chain = L2FWD_CRYPTO_AEAD;
		return 0;
	}

	return -1;
}

/** Parse crypto cipher algo option command line argument */
static int
parse_cipher_algo(enum rte_crypto_cipher_algorithm *algo, char *optarg)
{

	if (rte_cryptodev_get_cipher_algo_enum(algo, optarg) < 0) {
		RTE_LOG(ERR, USER1, "Cipher algorithm specified "
				"not supported!\n");
		return -1;
	}

	return 0;
}

/** Parse crypto cipher operation command line argument */
static int
parse_cipher_op(enum rte_crypto_cipher_operation *op, char *optarg)
{
	if (strcmp("ENCRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
		return 0;
	} else if (strcmp("DECRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		return 0;
	}

	printf("Cipher operation not supported!\n");
	return -1;
}

/** Parse crypto key command line argument */
static int
parse_key(uint8_t *data, char *input_arg)
{
	unsigned byte_count;
	char *token;

	errno = 0;
	for (byte_count = 0, token = strtok(input_arg, ":");
			(byte_count < MAX_KEY_SIZE) && (token != NULL);
			token = strtok(NULL, ":")) {

		int number = (int)strtol(token, NULL, 16);

		if (errno == EINVAL || errno == ERANGE || number > 0xFF)
			return -1;

		data[byte_count++] = (uint8_t)number;
	}

	return byte_count;
}

/** Parse size param*/
static int
parse_size(int *size, const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		n = 0;

	if (n == 0) {
		printf("invalid size\n");
		return -1;
	}

	*size = n;
	return 0;
}

/** Parse crypto cipher operation command line argument */
static int
parse_auth_algo(enum rte_crypto_auth_algorithm *algo, char *optarg)
{
	if (rte_cryptodev_get_auth_algo_enum(algo, optarg) < 0) {
		RTE_LOG(ERR, USER1, "Authentication algorithm specified "
				"not supported!\n");
		return -1;
	}

	return 0;
}

static int
parse_auth_op(enum rte_crypto_auth_operation *op, char *optarg)
{
	if (strcmp("VERIFY", optarg) == 0) {
		*op = RTE_CRYPTO_AUTH_OP_VERIFY;
		return 0;
	} else if (strcmp("GENERATE", optarg) == 0) {
		*op = RTE_CRYPTO_AUTH_OP_GENERATE;
		return 0;
	}

	printf("Authentication operation specified not supported!\n");
	return -1;
}

static int
parse_aead_algo(enum rte_crypto_aead_algorithm *algo, char *optarg)
{
	if (rte_cryptodev_get_aead_algo_enum(algo, optarg) < 0) {
		RTE_LOG(ERR, USER1, "AEAD algorithm specified "
				"not supported!\n");
		return -1;
	}

	return 0;
}

static int
parse_aead_op(enum rte_crypto_aead_operation *op, char *optarg)
{
	if (strcmp("ENCRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
		return 0;
	} else if (strcmp("DECRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_AEAD_OP_DECRYPT;
		return 0;
	}

	printf("AEAD operation specified not supported!\n");
	return -1;
}
static int
parse_cryptodev_mask(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	uint64_t pm;

	/* parse hexadecimal string */
	pm = strtoul(q_arg, &end, 16);
	if ((pm == '\0') || (end == NULL) || (*end != '\0'))
		pm = 0;

	options->cryptodev_mask = pm;
	if (options->cryptodev_mask == 0) {
		printf("invalid cryptodev_mask specified\n");
		return -1;
	}

	return 0;
}

/** Parse long options 将结果填入option中*/
static int
l2fwd_crypto_parse_args_long_options(struct l2fwd_crypto_options *options,
		struct option *lgopts, int option_index)
{
	int retval;

	if (strcmp(lgopts[option_index].name, "cdev_type") == 0) {
		retval = parse_cryptodev_type(&options->type, optarg);
		if (retval == 0)
			snprintf(options->string_type, MAX_STR_LEN,
				"%s", optarg);
		return retval;
	}

	else if (strcmp(lgopts[option_index].name, "chain") == 0)
		return parse_crypto_opt_chain(options, optarg);

	/* Cipher options */
	else if (strcmp(lgopts[option_index].name, "cipher_algo") == 0)
		return parse_cipher_algo(&options->cipher_xform.cipher.algo,
				optarg);

	else if (strcmp(lgopts[option_index].name, "cipher_op") == 0)
		return parse_cipher_op(&options->cipher_xform.cipher.op,
				optarg);

	else if (strcmp(lgopts[option_index].name, "cipher_key") == 0) {
		options->ckey_param = 1;
		options->cipher_xform.cipher.key.length =
			parse_key(options->cipher_xform.cipher.key.data, optarg);
		if (options->cipher_xform.cipher.key.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "cipher_key_random_size") == 0)
		return parse_size(&options->ckey_random_size, optarg);

	else if (strcmp(lgopts[option_index].name, "cipher_iv") == 0) {
		options->cipher_iv_param = 1;
		options->cipher_iv.length =
			parse_key(options->cipher_iv.data, optarg);
		if (options->cipher_iv.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "cipher_iv_random_size") == 0)
		return parse_size(&options->cipher_iv_random_size, optarg);

	/* Authentication options */
	else if (strcmp(lgopts[option_index].name, "auth_algo") == 0) {
		return parse_auth_algo(&options->auth_xform.auth.algo,
				optarg);
	}

	else if (strcmp(lgopts[option_index].name, "auth_op") == 0)
		return parse_auth_op(&options->auth_xform.auth.op,
				optarg);

	else if (strcmp(lgopts[option_index].name, "auth_key") == 0) {
		options->akey_param = 1;
		options->auth_xform.auth.key.length =
			parse_key(options->auth_xform.auth.key.data, optarg);
		if (options->auth_xform.auth.key.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "auth_key_random_size") == 0) {
		return parse_size(&options->akey_random_size, optarg);
	}

	else if (strcmp(lgopts[option_index].name, "auth_iv") == 0) {
		options->auth_iv_param = 1;
		options->auth_iv.length =
			parse_key(options->auth_iv.data, optarg);
		if (options->auth_iv.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "auth_iv_random_size") == 0)
		return parse_size(&options->auth_iv_random_size, optarg);

	/* AEAD options */
	else if (strcmp(lgopts[option_index].name, "aead_algo") == 0) {
		return parse_aead_algo(&options->aead_xform.aead.algo,
				optarg);
	}

	else if (strcmp(lgopts[option_index].name, "aead_op") == 0)
		return parse_aead_op(&options->aead_xform.aead.op,
				optarg);

	else if (strcmp(lgopts[option_index].name, "aead_key") == 0) {
		options->aead_key_param = 1;
		options->aead_xform.aead.key.length =
			parse_key(options->aead_xform.aead.key.data, optarg);
		if (options->aead_xform.aead.key.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "aead_key_random_size") == 0)
		return parse_size(&options->aead_key_random_size, optarg);


	else if (strcmp(lgopts[option_index].name, "aead_iv") == 0) {
		options->aead_iv_param = 1;
		options->aead_iv.length =
			parse_key(options->aead_iv.data, optarg);
		if (options->aead_iv.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "aead_iv_random_size") == 0)
		return parse_size(&options->aead_iv_random_size, optarg);

	else if (strcmp(lgopts[option_index].name, "aad") == 0) {
		options->aad_param = 1;
		options->aad.length =
			parse_key(options->aad.data, optarg);
		if (options->aad.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name, "aad_random_size") == 0) {
		return parse_size(&options->aad_random_size, optarg);
	}

	else if (strcmp(lgopts[option_index].name, "digest_size") == 0) {
		return parse_size(&options->digest_size, optarg);
	}

	else if (strcmp(lgopts[option_index].name, "sessionless") == 0) {
		options->sessionless = 1;
		return 0;
	}

	else if (strcmp(lgopts[option_index].name, "cryptodev_mask") == 0)
		return parse_cryptodev_mask(options, optarg);

	else if (strcmp(lgopts[option_index].name, "mac-updating") == 0) {
		options->mac_updating = 1;
		return 0;
	}

	else if (strcmp(lgopts[option_index].name, "no-mac-updating") == 0) {
		options->mac_updating = 0;
		return 0;
	}

	return -1;
}

/** Parse port mask */
static int
l2fwd_crypto_parse_portmask(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(q_arg, &end, 16);
	if ((pm == '\0') || (end == NULL) || (*end != '\0'))
		pm = 0;

	options->portmask = pm;
	if (options->portmask == 0) {
		printf("invalid portmask specified\n");
		return -1;
	}

	return pm;
}

/** Parse number of queues */
static int
l2fwd_crypto_parse_nqueue(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		n = 0;
	else if (n >= MAX_RX_QUEUE_PER_LCORE)
		n = 0;

	options->nb_ports_per_lcore = n;
	if (options->nb_ports_per_lcore == 0) {
		printf("invalid number of ports selected\n");
		return -1;
	}

	return 0;
}

/** Parse timer period */
static int
l2fwd_crypto_parse_timer_period(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse number string */
	n = (unsigned)strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		n = 0;

	if (n >= MAX_TIMER_PERIOD) {
		printf("Warning refresh period specified %lu is greater than "
				"max value %lu! using max value",
				n, MAX_TIMER_PERIOD);
		n = MAX_TIMER_PERIOD;
	}

	options->refresh_period = n * 1000 * TIMER_MILLISECOND;

	return 0;
}

/** Generate default options for application */
static void
l2fwd_crypto_default_options(struct l2fwd_crypto_options *options)
{
	options->portmask = 0xffffffff;
	options->nb_ports_per_lcore = 1;
	options->refresh_period = 10000;
	options->single_lcore = 0;
	options->sessionless = 0;

	options->xform_chain = L2FWD_CRYPTO_CIPHER_HASH;

	/* Cipher Data */
	options->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	options->cipher_xform.next = NULL;
	options->ckey_param = 0;
	options->ckey_random_size = -1;
	options->cipher_xform.cipher.key.length = 0;
	options->cipher_iv_param = 0;
	options->cipher_iv_random_size = -1;
	options->cipher_iv.length = 0;

	options->cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
	options->cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;

	/* Authentication Data */
	options->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	options->auth_xform.next = NULL;
	options->akey_param = 0;
	options->akey_random_size = -1;
	options->auth_xform.auth.key.length = 0;
	options->auth_iv_param = 0;
	options->auth_iv_random_size = -1;
	options->auth_iv.length = 0;

	options->auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
	options->auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;

	/* AEAD Data */
	options->aead_xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	options->aead_xform.next = NULL;
	options->aead_key_param = 0;
	options->aead_key_random_size = -1;
	options->aead_xform.aead.key.length = 0;
	options->aead_iv_param = 0;
	options->aead_iv_random_size = -1;
	options->aead_iv.length = 0;

	options->auth_xform.aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
	options->auth_xform.aead.op = RTE_CRYPTO_AEAD_OP_ENCRYPT;

	options->aad_param = 0;
	options->aad_random_size = -1;
	options->aad.length = 0;

	options->digest_size = -1;

	options->type = CDEV_TYPE_ANY;
	options->cryptodev_mask = UINT64_MAX;

	options->mac_updating = 1;
}

static void
display_cipher_info(struct l2fwd_crypto_options *options)
{
	printf("\n---- Cipher information ---\n");
	printf("Algorithm: %s\n",
		rte_crypto_cipher_algorithm_strings[options->cipher_xform.cipher.algo]);
	rte_hexdump(stdout, "Cipher key:",
			options->cipher_xform.cipher.key.data,
			options->cipher_xform.cipher.key.length);
	rte_hexdump(stdout, "IV:", options->cipher_iv.data, options->cipher_iv.length);
}

static void
display_auth_info(struct l2fwd_crypto_options *options)
{
	printf("\n---- Authentication information ---\n");
	printf("Algorithm: %s\n",
		rte_crypto_auth_algorithm_strings[options->auth_xform.auth.algo]);
	rte_hexdump(stdout, "Auth key:",
			options->auth_xform.auth.key.data,
			options->auth_xform.auth.key.length);
	rte_hexdump(stdout, "IV:", options->auth_iv.data, options->auth_iv.length);
}

static void
display_aead_info(struct l2fwd_crypto_options *options)
{
	printf("\n---- AEAD information ---\n");
	printf("Algorithm: %s\n",
		rte_crypto_aead_algorithm_strings[options->aead_xform.aead.algo]);
	rte_hexdump(stdout, "AEAD key:",
			options->aead_xform.aead.key.data,
			options->aead_xform.aead.key.length);
	rte_hexdump(stdout, "IV:", options->aead_iv.data, options->aead_iv.length);
	rte_hexdump(stdout, "AAD:", options->aad.data, options->aad.length);
}

static void
l2fwd_crypto_options_print(struct l2fwd_crypto_options *options)
{
	char string_cipher_op[MAX_STR_LEN];
	char string_auth_op[MAX_STR_LEN];
	char string_aead_op[MAX_STR_LEN];

	if (options->cipher_xform.cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		strcpy(string_cipher_op, "Encrypt");
	else
		strcpy(string_cipher_op, "Decrypt");

	if (options->auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_GENERATE)
		strcpy(string_auth_op, "Auth generate");
	else
		strcpy(string_auth_op, "Auth verify");

	if (options->aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_ENCRYPT)
		strcpy(string_aead_op, "Authenticated encryption");
	else
		strcpy(string_aead_op, "Authenticated decryption");


	printf("Options:-\nn");
	printf("portmask: %x\n", options->portmask);
	printf("ports per lcore: %u\n", options->nb_ports_per_lcore);
	printf("refresh period : %u\n", options->refresh_period);
	printf("single lcore mode: %s\n",
			options->single_lcore ? "enabled" : "disabled");
	printf("stats_printing: %s\n",
			options->refresh_period == 0 ? "disabled" : "enabled");

	printf("sessionless crypto: %s\n",
			options->sessionless ? "enabled" : "disabled");

	if (options->ckey_param && (options->ckey_random_size != -1))
		printf("Cipher key already parsed, ignoring size of random key\n");

	if (options->akey_param && (options->akey_random_size != -1))
		printf("Auth key already parsed, ignoring size of random key\n");

	if (options->cipher_iv_param && (options->cipher_iv_random_size != -1))
		printf("Cipher IV already parsed, ignoring size of random IV\n");

	if (options->auth_iv_param && (options->auth_iv_random_size != -1))
		printf("Auth IV already parsed, ignoring size of random IV\n");

	if (options->aad_param && (options->aad_random_size != -1))
		printf("AAD already parsed, ignoring size of random AAD\n");

	printf("\nCrypto chain: ");
	switch (options->xform_chain) {
	case L2FWD_CRYPTO_AEAD:
		printf("Input --> %s --> Output\n", string_aead_op);
		display_aead_info(options);
		break;
	case L2FWD_CRYPTO_CIPHER_HASH:
		printf("Input --> %s --> %s --> Output\n",
			string_cipher_op, string_auth_op);
		display_cipher_info(options);
		display_auth_info(options);
		break;
	case L2FWD_CRYPTO_HASH_CIPHER:
		printf("Input --> %s --> %s --> Output\n",
			string_auth_op, string_cipher_op);
		display_cipher_info(options);
		display_auth_info(options);
		break;
	case L2FWD_CRYPTO_HASH_ONLY:
		printf("Input --> %s --> Output\n", string_auth_op);
		display_auth_info(options);
		break;
	case L2FWD_CRYPTO_CIPHER_ONLY:
		printf("Input --> %s --> Output\n", string_cipher_op);
		display_cipher_info(options);
		break;
	}
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_crypto_parse_args(struct l2fwd_crypto_options *options,
		int argc, char **argv)
{
	int opt, retval, option_index;
	char **argvopt = argv, *prgname = argv[0];

	static struct option lgopts[] = {
			{ "sessionless", no_argument, 0, 0 },

			{ "cdev_type", required_argument, 0, 0 },
			{ "chain", required_argument, 0, 0 },

			{ "cipher_algo", required_argument, 0, 0 },
			{ "cipher_op", required_argument, 0, 0 },
			{ "cipher_key", required_argument, 0, 0 },
			{ "cipher_key_random_size", required_argument, 0, 0 },
			{ "cipher_iv", required_argument, 0, 0 },
			{ "cipher_iv_random_size", required_argument, 0, 0 },

			{ "auth_algo", required_argument, 0, 0 },
			{ "auth_op", required_argument, 0, 0 },
			{ "auth_key", required_argument, 0, 0 },
			{ "auth_key_random_size", required_argument, 0, 0 },
			{ "auth_iv", required_argument, 0, 0 },
			{ "auth_iv_random_size", required_argument, 0, 0 },

			{ "aead_algo", required_argument, 0, 0 },
			{ "aead_op", required_argument, 0, 0 },
			{ "aead_key", required_argument, 0, 0 },
			{ "aead_key_random_size", required_argument, 0, 0 },
			{ "aead_iv", required_argument, 0, 0 },
			{ "aead_iv_random_size", required_argument, 0, 0 },

			{ "aad", required_argument, 0, 0 },
			{ "aad_random_size", required_argument, 0, 0 },

			{ "digest_size", required_argument, 0, 0 },

			{ "sessionless", no_argument, 0, 0 },
			{ "cryptodev_mask", required_argument, 0, 0},

			{ "mac-updating", no_argument, 0, 0},
			{ "no-mac-updating", no_argument, 0, 0},

			{ NULL, 0, 0, 0 }
	};
	//将默认配置写入option
	l2fwd_crypto_default_options(options);
	//解析执行命令行
	while ((opt = getopt_long(argc, argvopt, "p:q:sT:", lgopts,
			&option_index)) != EOF) 
	{
		switch (opt) 
		{
		/* long options 加解密、验证等命令的解析，结果在option中*/
		case 0:
			retval = l2fwd_crypto_parse_args_long_options(options,
					lgopts, option_index);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;

		/* portmask */
		case 'p':
			retval = l2fwd_crypto_parse_portmask(options, optarg);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			retval = l2fwd_crypto_parse_nqueue(options, optarg);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;

		/* single  */
		case 's':
			options->single_lcore = 1;

			break;

		/* timer period */
		case 'T':
			retval = l2fwd_crypto_parse_timer_period(options,
					optarg);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;

		default:
			l2fwd_crypto_usage(prgname);
			return -1;
		}
	}


	if (optind >= 0)
		argv[optind-1] = prgname;

	retval = optind-1;
	optind = 1; /* reset getopt lib */

	return retval;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Check if device has to be HW/SW or any */
static int
check_type(const struct l2fwd_crypto_options *options,
		const struct rte_cryptodev_info *dev_info)
{
	if (options->type == CDEV_TYPE_HW &&
			(dev_info->feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED))
		return 0;
	if (options->type == CDEV_TYPE_SW &&
			!(dev_info->feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED))
		return 0;
	if (options->type == CDEV_TYPE_ANY)
		return 0;

	return -1;
}

static const struct rte_cryptodev_capabilities *
check_device_support_cipher_algo(const struct l2fwd_crypto_options *options,
		const struct rte_cryptodev_info *dev_info,
		uint8_t cdev_id)
{
	unsigned int i = 0;
	const struct rte_cryptodev_capabilities *cap = &dev_info->capabilities[0];
	enum rte_crypto_cipher_algorithm cap_cipher_algo;
	enum rte_crypto_cipher_algorithm opt_cipher_algo =
					options->cipher_xform.cipher.algo;

	while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		cap_cipher_algo = cap->sym.cipher.algo;
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
			if (cap_cipher_algo == opt_cipher_algo) {
				if (check_type(options, dev_info) == 0)
					break;
			}
		}
		cap = &dev_info->capabilities[++i];
	}

	if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		printf("Algorithm %s not supported by cryptodev %u"
			" or device not of preferred type (%s)\n",
			rte_crypto_cipher_algorithm_strings[opt_cipher_algo],
			cdev_id,
			options->string_type);
		return NULL;
	}

	return cap;
}

static const struct rte_cryptodev_capabilities *
check_device_support_auth_algo(const struct l2fwd_crypto_options *options,
		const struct rte_cryptodev_info *dev_info,
		uint8_t cdev_id)
{
	unsigned int i = 0;
	const struct rte_cryptodev_capabilities *cap = &dev_info->capabilities[0];
	enum rte_crypto_auth_algorithm cap_auth_algo;
	enum rte_crypto_auth_algorithm opt_auth_algo =
					options->auth_xform.auth.algo;

	while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		cap_auth_algo = cap->sym.auth.algo;
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH) {
			if (cap_auth_algo == opt_auth_algo) {
				if (check_type(options, dev_info) == 0)
					break;
			}
		}
		cap = &dev_info->capabilities[++i];
	}

	if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		printf("Algorithm %s not supported by cryptodev %u"
			" or device not of preferred type (%s)\n",
			rte_crypto_auth_algorithm_strings[opt_auth_algo],
			cdev_id,
			options->string_type);
		return NULL;
	}

	return cap;
}

static const struct rte_cryptodev_capabilities *
check_device_support_aead_algo(const struct l2fwd_crypto_options *options,
		const struct rte_cryptodev_info *dev_info,
		uint8_t cdev_id)
{
	unsigned int i = 0;
	const struct rte_cryptodev_capabilities *cap = &dev_info->capabilities[0];
	enum rte_crypto_aead_algorithm cap_aead_algo;
	enum rte_crypto_aead_algorithm opt_aead_algo =
					options->aead_xform.aead.algo;

	while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		cap_aead_algo = cap->sym.aead.algo;
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) {
			if (cap_aead_algo == opt_aead_algo) {
				if (check_type(options, dev_info) == 0)
					break;
			}
		}
		cap = &dev_info->capabilities[++i];
	}

	if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		printf("Algorithm %s not supported by cryptodev %u"
			" or device not of preferred type (%s)\n",
			rte_crypto_aead_algorithm_strings[opt_aead_algo],
			cdev_id,
			options->string_type);
		return NULL;
	}

	return cap;
}

/* Check if the device is enabled by cryptodev_mask */
static int
check_cryptodev_mask(struct l2fwd_crypto_options *options,
		uint8_t cdev_id)
{
	if (options->cryptodev_mask & (1 << cdev_id))
		return 0;

	return -1;
}

static inline int
check_supported_size(uint16_t length, uint16_t min, uint16_t max,
		uint16_t increment)
{
	uint16_t supp_size;

	/* Single value */
	if (increment == 0) {
		if (length == min)
			return 0;
		else
			return -1;
	}

	/* Range of values */
	for (supp_size = min; supp_size <= max; supp_size += increment) {
		if (length == supp_size)
			return 0;
	}

	return -1;
}

static int
check_iv_param(const struct rte_crypto_param_range *iv_range_size,
		unsigned int iv_param, int iv_random_size,
		uint16_t *iv_length)
{
	/*
	 * Check if length of provided IV is supported
	 * by the algorithm chosen.
	 */
	if (iv_param) {
		if (check_supported_size(*iv_length,
				iv_range_size->min,
				iv_range_size->max,
				iv_range_size->increment)
					!= 0) {
			printf("Unsupported IV length\n");
			return -1;
		}
	/*
	 * Check if length of IV to be randomly generated
	 * is supported by the algorithm chosen.
	 */
	} else if (iv_random_size != -1) {
		if (check_supported_size(iv_random_size,
				iv_range_size->min,
				iv_range_size->max,
				iv_range_size->increment)
					!= 0) {
			printf("Unsupported IV length\n");
			return -1;
		}
		*iv_length = iv_random_size;
	/* No size provided, use minimum size. */
	} else
		*iv_length = iv_range_size->min;

	return 0;
}
//初始化加密设备
/* @brief 初始化并激活Crypto device 
* @param	options 		命令行参数（加密算法、认证算法、加密密钥等）
* @param	nb_ports		已经激活的网口数量
* @param	enabled_cdevs	存储启动的crypto_dev数组
* @return	enabled_cdev_count	激活的crypto_dev数量
**/
static int
initialize_cryptodevs(struct l2fwd_crypto_options *options, unsigned nb_ports,
		uint8_t *enabled_cdevs)
{
	unsigned int cdev_id, cdev_count, enabled_cdev_count = 0;
	const struct rte_cryptodev_capabilities *cap;
	unsigned int sess_sz, max_sess_sz = 0;
	int retval;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		printf("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		sess_sz = rte_cryptodev_get_private_session_size(cdev_id);
		if (sess_sz > max_sess_sz)
			max_sess_sz = sess_sz;
	}

	for (cdev_id = 0; cdev_id < cdev_count && enabled_cdev_count < nb_ports;
			cdev_id++) {
		struct rte_cryptodev_qp_conf qp_conf;
		struct rte_cryptodev_info dev_info;
		retval = rte_cryptodev_socket_id(cdev_id);

		if (retval < 0) {
			printf("Invalid crypto device id used\n");
			return -1;
		}

		uint8_t socket_id = (uint8_t) retval;

		struct rte_cryptodev_config conf = {
			.nb_queue_pairs = 1,
			.socket_id = socket_id,
		};

		if (check_cryptodev_mask(options, (uint8_t)cdev_id))
			continue;
		/* 获取Crypto device的信息 */
		rte_cryptodev_info_get(cdev_id, &dev_info);

		if (session_pool_socket[socket_id] == NULL) {
			char mp_name[RTE_MEMPOOL_NAMESIZE];
			struct rte_mempool *sess_mp;

			snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
				"sess_mp_%u", socket_id);

			/*
			 * Create enough objects for session headers and
			 * device private data
			 */
			sess_mp = rte_mempool_create(mp_name,
						MAX_SESSIONS * 2,
						max_sess_sz,
						SESSION_POOL_CACHE_SIZE,
						0, NULL, NULL, NULL,
						NULL, socket_id,
						0);

			if (sess_mp == NULL) {
				printf("Cannot create session pool on socket %d\n",
					socket_id);
				return -ENOMEM;
			}

			printf("Allocated session pool on socket %d\n", socket_id);
			session_pool_socket[socket_id] = sess_mp;
		}

		/* Set AEAD parameters */
		if (options->xform_chain == L2FWD_CRYPTO_AEAD) {
			/* Check if device supports AEAD algo */
			cap = check_device_support_aead_algo(options, &dev_info,
							cdev_id);
			if (cap == NULL)
				continue;

			options->block_size = cap->sym.aead.block_size;

			check_iv_param(&cap->sym.aead.iv_size,
					options->aead_iv_param,
					options->aead_iv_random_size,
					&options->aead_iv.length);

			/*
			 * Check if length of provided AEAD key is supported
			 * by the algorithm chosen.
			 */
			if (options->aead_key_param) {
				if (check_supported_size(
						options->aead_xform.aead.key.length,
						cap->sym.aead.key_size.min,
						cap->sym.aead.key_size.max,
						cap->sym.aead.key_size.increment)
							!= 0) {
					printf("Unsupported aead key length\n");
					return -1;
				}
			/*
			 * Check if length of the aead key to be randomly generated
			 * is supported by the algorithm chosen.
			 */
			} else if (options->aead_key_random_size != -1) {
				if (check_supported_size(options->aead_key_random_size,
						cap->sym.aead.key_size.min,
						cap->sym.aead.key_size.max,
						cap->sym.aead.key_size.increment)
							!= 0) {
					printf("Unsupported aead key length\n");
					return -1;
				}
				options->aead_xform.aead.key.length =
							options->aead_key_random_size;
			/* No size provided, use minimum size. */
			} else
				options->aead_xform.aead.key.length =
						cap->sym.aead.key_size.min;

			if (!options->aead_key_param)
				generate_random_key(
					options->aead_xform.aead.key.data,
					options->aead_xform.aead.key.length);

			/*
			 * Check if length of provided AAD is supported
			 * by the algorithm chosen.
			 */
			if (options->aad_param) {
				if (check_supported_size(options->aad.length,
						cap->sym.aead.aad_size.min,
						cap->sym.aead.aad_size.max,
						cap->sym.aead.aad_size.increment)
							!= 0) {
					printf("Unsupported AAD length\n");
					return -1;
				}
			/*
			 * Check if length of AAD to be randomly generated
			 * is supported by the algorithm chosen.
			 */
			} else if (options->aad_random_size != -1) {
				if (check_supported_size(options->aad_random_size,
						cap->sym.aead.aad_size.min,
						cap->sym.aead.aad_size.max,
						cap->sym.aead.aad_size.increment)
							!= 0) {
					printf("Unsupported AAD length\n");
					return -1;
				}
				options->aad.length = options->aad_random_size;
			/* No size provided, use minimum size. */
			} else
				options->aad.length = cap->sym.auth.aad_size.min;

			options->aead_xform.aead.aad_length =
						options->aad.length;

			/* Check if digest size is supported by the algorithm. */
			if (options->digest_size != -1) {
				if (check_supported_size(options->digest_size,
						cap->sym.aead.digest_size.min,
						cap->sym.aead.digest_size.max,
						cap->sym.aead.digest_size.increment)
							!= 0) {
					printf("Unsupported digest length\n");
					return -1;
				}
				options->aead_xform.aead.digest_length =
							options->digest_size;
			/* No size provided, use minimum size. */
			} else
				options->aead_xform.aead.digest_length =
						cap->sym.aead.digest_size.min;
		}

		/* Set cipher parameters 设置加密参数*/
		if (options->xform_chain == L2FWD_CRYPTO_CIPHER_HASH ||
				options->xform_chain == L2FWD_CRYPTO_HASH_CIPHER ||
				options->xform_chain == L2FWD_CRYPTO_CIPHER_ONLY) {
			/* Check if device supports cipher algo */
			cap = check_device_support_cipher_algo(options, &dev_info,
							cdev_id);
			if (cap == NULL)
				continue;

			options->block_size = cap->sym.cipher.block_size;

			check_iv_param(&cap->sym.cipher.iv_size,
					options->cipher_iv_param,
					options->cipher_iv_random_size,
					&options->cipher_iv.length);

			/*
			 * Check if length of provided cipher key is supported
			 * by the algorithm chosen.
			 */
			if (options->ckey_param) {
				if (check_supported_size(
						options->cipher_xform.cipher.key.length,
						cap->sym.cipher.key_size.min,
						cap->sym.cipher.key_size.max,
						cap->sym.cipher.key_size.increment)
							!= 0) {
					printf("Unsupported cipher key length\n");
					return -1;
				}
			/*
			 * Check if length of the cipher key to be randomly generated
			 * is supported by the algorithm chosen.
			 */
			} else if (options->ckey_random_size != -1) {
				if (check_supported_size(options->ckey_random_size,
						cap->sym.cipher.key_size.min,
						cap->sym.cipher.key_size.max,
						cap->sym.cipher.key_size.increment)
							!= 0) {
					printf("Unsupported cipher key length\n");
					return -1;
				}
				options->cipher_xform.cipher.key.length =
							options->ckey_random_size;
			/* No size provided, use minimum size. */
			} else
				options->cipher_xform.cipher.key.length =
						cap->sym.cipher.key_size.min;

			if (!options->ckey_param)
				generate_random_key(
					options->cipher_xform.cipher.key.data,
					options->cipher_xform.cipher.key.length);

		}

		/* Set auth parameters 设置认证参数*/
		if (options->xform_chain == L2FWD_CRYPTO_CIPHER_HASH ||
				options->xform_chain == L2FWD_CRYPTO_HASH_CIPHER ||
				options->xform_chain == L2FWD_CRYPTO_HASH_ONLY) {
			/* Check if device supports auth algo */
			cap = check_device_support_auth_algo(options, &dev_info,
							cdev_id);
			if (cap == NULL)
				continue;

			check_iv_param(&cap->sym.auth.iv_size,
					options->auth_iv_param,
					options->auth_iv_random_size,
					&options->auth_iv.length);
			/*
			 * Check if length of provided auth key is supported
			 * by the algorithm chosen.
			 */
			if (options->akey_param) {
				if (check_supported_size(
						options->auth_xform.auth.key.length,
						cap->sym.auth.key_size.min,
						cap->sym.auth.key_size.max,
						cap->sym.auth.key_size.increment)
							!= 0) {
					printf("Unsupported auth key length\n");
					return -1;
				}
			/*
			 * Check if length of the auth key to be randomly generated
			 * is supported by the algorithm chosen.
			 */
			} else if (options->akey_random_size != -1) {
				if (check_supported_size(options->akey_random_size,
						cap->sym.auth.key_size.min,
						cap->sym.auth.key_size.max,
						cap->sym.auth.key_size.increment)
							!= 0) {
					printf("Unsupported auth key length\n");
					return -1;
				}
				options->auth_xform.auth.key.length =
							options->akey_random_size;
			/* No size provided, use minimum size. */
			} else
				options->auth_xform.auth.key.length =
						cap->sym.auth.key_size.min;

			if (!options->akey_param)
				generate_random_key(
					options->auth_xform.auth.key.data,
					options->auth_xform.auth.key.length);

			/* Check if digest size is supported by the algorithm. */
			if (options->digest_size != -1) {
				if (check_supported_size(options->digest_size,
						cap->sym.auth.digest_size.min,
						cap->sym.auth.digest_size.max,
						cap->sym.auth.digest_size.increment)
							!= 0) {
					printf("Unsupported digest length\n");
					return -1;
				}
				options->auth_xform.auth.digest_length =
							options->digest_size;
			/* No size provided, use minimum size. */
			} else
				options->auth_xform.auth.digest_length =
						cap->sym.auth.digest_size.min;
		}

		retval = rte_cryptodev_configure(cdev_id, &conf);
		if (retval < 0) {
			printf("Failed to configure cryptodev %u", cdev_id);
			return -1;
		}

		qp_conf.nb_descriptors = 2048;

		retval = rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf,
				socket_id, session_pool_socket[socket_id]);
		if (retval < 0) {
			printf("Failed to setup queue pair %u on cryptodev %u",
					0, cdev_id);
			return -1;
		}

		retval = rte_cryptodev_start(cdev_id);
		if (retval < 0) {
			printf("Failed to start device %u: error %d\n",
					cdev_id, retval);
			return -1;
		}

		l2fwd_enabled_crypto_mask |= (((uint64_t)1) << cdev_id);

		enabled_cdevs[cdev_id] = 1;
		enabled_cdev_count++;
	}

	return enabled_cdev_count;
}
/*
* @brief 初始化并启动所有网口
* @param 命令行参数结构体
* @return 返回启动的网口数量
**/
static int
initialize_ports(struct l2fwd_crypto_options *options)
{
	uint8_t last_portid, portid;
	unsigned enabled_portcount = 0;
	/* 获取网口数量 */
	unsigned nb_ports = rte_eth_dev_count();

	if (nb_ports == 0) {
		printf("No Ethernet ports - bye\n");
		return -1;
	}

	/* Reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;

	for (last_portid = 0, portid = 0; portid < nb_ports; portid++) {
		int retval;

		/* Skip ports that are not enabled 忽略未启用的物理端口*/
		if ((options->portmask & (1 << portid)) == 0)
			continue;

		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		fflush(stdout);
		/* 根据port_conf参数配置一个网口的信息, 同时设1个发送队列和1个接收队列 */
		retval = rte_eth_dev_configure(portid, 1, 1, &port_conf);
		if (retval < 0) {
			printf("Cannot configure device: err=%d, port=%u\n",
				  retval, (unsigned) portid);
			return -1;
		}

		retval = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
							  &nb_txd);
		if (retval < 0) {
			printf("Cannot adjust number of descriptors: err=%d, port=%u\n",
				retval, (unsigned) portid);
			return -1;
		}

		/* 在每个物理网口上初始化一个接收队列 init one RX queue */
		fflush(stdout);
		retval = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     NULL, l2fwd_pktmbuf_pool);
		if (retval < 0) {
			printf("rte_eth_rx_queue_setup:err=%d, port=%u\n",
					retval, (unsigned) portid);
			return -1;
		}

		/* 在每个物理端口上初始化一个发送队列 init one TX queue on each port */
		fflush(stdout);
		retval = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				NULL);
		if (retval < 0) {
			printf("rte_eth_tx_queue_setup:err=%d, port=%u\n",
				retval, (unsigned) portid);

			return -1;
		}

		/* Start device */
		retval = rte_eth_dev_start(portid);
		if (retval < 0) {
			printf("rte_eth_dev_start:err=%d, port=%u\n",
					retval, (unsigned) portid);
			return -1;
		}
		//设为混杂模式
		rte_eth_promiscuous_enable(portid);
		/* 获取物理网口的mac地址 */
		rte_eth_macaddr_get(portid, &l2fwd_ports_eth_addr[portid]);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));

		/* Setup port forwarding table 如果是有偶数个物理端口，设为相邻两个物理端口对发*/
		if (enabled_portcount % 2) {
			l2fwd_dst_ports[portid] = last_portid;
			l2fwd_dst_ports[last_portid] = portid;
		} else {/* 将这个portid设为最后一个portid */
			last_portid = portid;
		}

		l2fwd_enabled_port_mask |= (1 << portid);
		enabled_portcount++;//更新已启用的物理端口的总数
	}

	if (enabled_portcount == 1) {
		l2fwd_dst_ports[last_portid] = last_portid;
	} else if (enabled_portcount % 2) {
		printf("odd number of ports in portmask- bye\n");
		return -1;
	}
	//检查所有物理端口的连接状态
	check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);

	return enabled_portcount;
}

static void
reserve_key_memory(struct l2fwd_crypto_options *options)
{
	options->cipher_xform.cipher.key.data = rte_malloc("crypto key",
						MAX_KEY_SIZE, 0);
	if (options->cipher_xform.cipher.key.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for cipher key");

	options->auth_xform.auth.key.data = rte_malloc("auth key",
						MAX_KEY_SIZE, 0);
	if (options->auth_xform.auth.key.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for auth key");

	options->aead_xform.aead.key.data = rte_malloc("aead key",
						MAX_KEY_SIZE, 0);
	if (options->aead_xform.aead.key.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for AEAD key");

	options->cipher_iv.data = rte_malloc("cipher iv", MAX_KEY_SIZE, 0);
	if (options->cipher_iv.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for cipher IV");

	options->auth_iv.data = rte_malloc("auth iv", MAX_KEY_SIZE, 0);
	if (options->auth_iv.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for auth IV");

	options->aead_iv.data = rte_malloc("aead_iv", MAX_KEY_SIZE, 0);
	if (options->aead_iv.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for AEAD iv");

	options->aad.data = rte_malloc("aad", MAX_KEY_SIZE, 0);
	if (options->aad.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for AAD");
	options->aad.phys_addr = rte_malloc_virt2phy(options->aad.data);
}
//主函数
int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	struct l2fwd_crypto_options options;//加密选项配置
	hello();
	uint8_t nb_ports, nb_cryptodevs, portid, cdev_id;
	unsigned lcore_id, rx_lcore_id;
	int ret, enabled_cdevcount, enabled_portcount;
	uint8_t enabled_cdevs[RTE_CRYPTO_MAX_DEVS] = {0};

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* reserve memory for Cipher/Auth key and IV 申请储存空间用来存储密钥、IV等*/
	reserve_key_memory(&options);
	
	/* parse application arguments (after the EAL ones) 处理入参，结果保存进配置*/
	ret = l2fwd_crypto_parse_args(&options, argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD-CRYPTO arguments\n");

	printf("MAC updating %s\n",options.mac_updating ? "enabled" : "disabled");
	
	// 每个内核线程两个拥有2个内存池
	/* create the mbuf pool 创建内存池*/
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 512,
			sizeof(struct rte_crypto_op),
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* create crypto op pool 创建加密内存池*/
	l2fwd_crypto_op_pool =   rte_crypto_op_pool_create("crypto_op_pool",
			RTE_CRYPTO_OP_TYPE_SYMMETRIC, NB_MBUF, 128, MAXIMUM_IV_LENGTH,
			rte_socket_id());
	if (l2fwd_crypto_op_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create crypto op pool\n");

	/* Enable Ethernet ports 初始化以太网端口*/
	enabled_portcount = initialize_ports(&options);
	if (enabled_portcount < 1)
		rte_exit(EXIT_FAILURE, "Failed to initial Ethernet ports\n");

	nb_ports = rte_eth_dev_count();//计算可用的端口数量
	/* Initialize the port/queue configuration of each logical core */
	for (rx_lcore_id = 0, qconf = NULL, portid = 0;
			portid < nb_ports; portid++) 
	{
		/* skip ports that are not enabled 未使能，跳过*/
		if ((options.portmask & (1 << portid)) == 0)
			continue;

		if (options.single_lcore && qconf == NULL) 
		{	//如果该内核使能，则内核计数器+1
			while (rte_lcore_is_enabled(rx_lcore_id) == 0) 
			{
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,"Not enough cores\n");
			}
		} 
		else if (!options.single_lcore) 
		{
			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
			       lcore_queue_conf[rx_lcore_id].nb_rx_ports ==
			       options.nb_ports_per_lcore) 
			{
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,"Not enough cores\n");
			}
		}

		/* Assigned a new logical core in the loop above. */
		if (qconf != &lcore_queue_conf[rx_lcore_id])
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->rx_port_list[qconf->nb_rx_ports] = portid;
		qconf->nb_rx_ports++;

		printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned)portid);
	}

	/* Enable Crypto devices */
	enabled_cdevcount = initialize_cryptodevs(&options, enabled_portcount,
			enabled_cdevs);
	if (enabled_cdevcount < 0)
		rte_exit(EXIT_FAILURE, "Failed to initialize crypto devices\n");

	if (enabled_cdevcount < enabled_portcount)
		rte_exit(EXIT_FAILURE, "Number of capable crypto devices (%d) "
				"has to be more or equal to number of ports (%d)\n",
				enabled_cdevcount, enabled_portcount);

	nb_cryptodevs = rte_cryptodev_count();

	/* Initialize the port/cryptodev configuration of each logical core */
	for (rx_lcore_id = 0, qconf = NULL, cdev_id = 0;
			cdev_id < nb_cryptodevs && enabled_cdevcount;
			cdev_id++)
	{
		/* Crypto op not supported by crypto device */
		if (!enabled_cdevs[cdev_id])
			continue;

		if (options.single_lcore && qconf == NULL)
		{
			while (rte_lcore_is_enabled(rx_lcore_id) == 0) 
			{
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,
							"Not enough cores\n");
			}
		} 
		else if (!options.single_lcore) 
		{
			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
			       lcore_queue_conf[rx_lcore_id].nb_crypto_devs ==
			       options.nb_ports_per_lcore) 
			{
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,
							"Not enough cores\n");
			}
		}

		/* Assigned a new logical core in the loop above. */
		if (qconf != &lcore_queue_conf[rx_lcore_id])
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->cryptodev_list[qconf->nb_crypto_devs] = cdev_id;
		qconf->nb_crypto_devs++;

		enabled_cdevcount--;

		printf("Lcore %u: cryptodev %u\n", rx_lcore_id,
				(unsigned)cdev_id);
	}

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, (void *)&options,
			CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) 
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}
