#ifndef __MAIN_H
#define __MAIN_H

enum cdev_type {
	CDEV_TYPE_ANY,
	CDEV_TYPE_HW,
	CDEV_TYPE_SW
};

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_STR_LEN 32
#define MAX_KEY_SIZE 128
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MAX_SESSIONS 32
#define SESSION_POOL_CACHE_SIZE 0

#define MAXIMUM_IV_LENGTH	16
#define IV_OFFSET		(sizeof(struct rte_crypto_op) + \
				sizeof(struct rte_crypto_sym_op))

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint64_t l2fwd_enabled_port_mask;
static uint64_t l2fwd_enabled_crypto_mask;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];


struct pkt_buffer {
	unsigned len;
	struct rte_mbuf *buffer[MAX_PKT_BURST];
};

struct op_buffer {
	unsigned len;
	struct rte_crypto_op *buffer[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

enum l2fwd_crypto_xform_chain {
	L2FWD_CRYPTO_CIPHER_HASH,
	L2FWD_CRYPTO_HASH_CIPHER,
	L2FWD_CRYPTO_CIPHER_ONLY,
	L2FWD_CRYPTO_HASH_ONLY,
	L2FWD_CRYPTO_AEAD
};

struct l2fwd_key {
	uint8_t *data;
	uint32_t length;
	phys_addr_t phys_addr;
};

struct l2fwd_iv {
	uint8_t *data;
	uint16_t length;
};

/** l2fwd crypto application command line options */
struct l2fwd_crypto_options {
	unsigned portmask;
	unsigned nb_ports_per_lcore;
	unsigned refresh_period;
	unsigned single_lcore:1;

	enum cdev_type type;     
	unsigned sessionless:1;

	enum l2fwd_crypto_xform_chain xform_chain;

	struct rte_crypto_sym_xform cipher_xform;//加解密配置
	unsigned ckey_param;
	int ckey_random_size;

	struct l2fwd_iv cipher_iv;
	unsigned int cipher_iv_param;
	int cipher_iv_random_size;

	struct rte_crypto_sym_xform auth_xform;
	uint8_t akey_param;
	int akey_random_size;

	struct l2fwd_iv auth_iv;
	unsigned int auth_iv_param;
	int auth_iv_random_size;

	struct rte_crypto_sym_xform aead_xform;
	unsigned int aead_key_param;
	int aead_key_random_size;

	struct l2fwd_iv aead_iv;
	unsigned int aead_iv_param;
	int aead_iv_random_size;

	struct l2fwd_key aad;
	unsigned aad_param;
	int aad_random_size;

	int digest_size;

	uint16_t block_size;
	char string_type[MAX_STR_LEN];

	uint64_t cryptodev_mask;

	unsigned int mac_updating;
};

/** l2fwd crypto lcore params */
struct l2fwd_crypto_params {
	uint8_t dev_id;
	uint8_t qp_id;

	unsigned digest_length;
	unsigned block_size;

	struct l2fwd_iv cipher_iv;
	struct l2fwd_iv auth_iv;
	struct l2fwd_iv aead_iv;
	struct l2fwd_key aad;
	struct rte_cryptodev_sym_session *session;

	uint8_t do_cipher;
	uint8_t do_hash;
	uint8_t do_aead;
	uint8_t hash_verify;

	enum rte_crypto_cipher_algorithm cipher_algo;
	enum rte_crypto_auth_algorithm auth_algo;
	enum rte_crypto_aead_algorithm aead_algo;
	//add enc or dec
	enum rte_crypto_cipher_operation cipher_op;//加密or解密
};

/** lcore configuration */
struct lcore_queue_conf {
	unsigned nb_rx_ports;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];

	unsigned nb_crypto_devs;
	unsigned cryptodev_list[MAX_RX_QUEUE_PER_LCORE];

	struct op_buffer op_buf[RTE_CRYPTO_MAX_DEVS];
	struct pkt_buffer pkt_buf[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_NONE,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *l2fwd_pktmbuf_pool;
struct rte_mempool *l2fwd_crypto_op_pool;
struct rte_mempool *session_pool_socket[RTE_MAX_NUMA_NODES] = { 0 };

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;

	uint64_t crypto_enqueued;
	uint64_t crypto_dequeued;

	uint64_t dropped;
} __rte_cache_aligned;

struct l2fwd_crypto_statistics {
	uint64_t enqueued;
	uint64_t dequeued;

	uint64_t errors;
} __rte_cache_aligned;

struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];
struct l2fwd_crypto_statistics crypto_statistics[RTE_CRYPTO_MAX_DEVS];

/* A tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400UL /* 1 day max */

/* default period is 10 seconds */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000;
#endif