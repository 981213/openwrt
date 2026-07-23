// SPDX-License-Identifier: GPL-2.0-only
/*
 * Siflower SF19A2890 hardware NAT offload engine
 *
 * The block at GMAC + 0x4000/0x6000 sits between the DWMAC MAC and DMA.  A
 * miss reaches the DMA rings; a hit is rewritten and looped to the MAC TX path.
 *
 * CSR16..23 and CSR30/31 hold up to eight LAN IPv4 networks and prefix
 * lengths.  A source in one of these global, VLAN-blind networks selects ENAT
 * (SNAT); other traffic uses the INAT (DNAT) hashes.  LAN and public prefixes
 * must therefore not overlap.
 *
 * IPv4 TCP/UDP flows use a bidirectional NAPT entry, three-level ENAT/INAT CRC
 * hashes, and shared VLAN, public-network, destination, MAC and PPPoE tables.
 * Hardware rewrites L2/VLAN/IP/ports/checksums and can push or remove PPPoE.
 * Table 24 is a read-clear counter table indexed by destination-MAC entry.
 *
 * Configuration starts by enabling symmetric mode with CSR1=0x0240004f.
 * TB_CONFIG=0x0fff0415 enables the tables, endian mode, CRC and DIP-based ARP.
 * Tables are written through the five-word indirect port; CSR2 bit 0 commits
 * LAN comparator changes.  Eight PPPoE header entries hold version/type and
 * session ID and are selected by each NAPT entry.
 *
 * The block shares DWMAC's software reset, which clears its CSRs and tables;
 * all configuration must be programmed again after a DWMAC reset.
 *
 * Copyright (C) 2026 Chuanhong Guo <gch981213@gmail.com>
 */

#include <linux/debugfs.h>
#include <linux/bitmap.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/iopoll.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/unaligned.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>

#include "sf19a2890-hnat.h"

#define HNAT_CSR_BASE			0x4000
#define HNAT_TABLE_BASE			0x6000
#define HNAT_CSR(n)			(HNAT_CSR_BASE + (n) * 4)
#define HNAT_CSR_LAN(n)		(HNAT_CSR_BASE + 0x40 + (n) * 4)
#define HNAT_CSR_LAN_MASK0		(HNAT_CSR_BASE + 0x80)
#define HNAT_CSR_LAN_MASK1		(HNAT_CSR_BASE + 0x84)
#define HNAT_CSR33			(HNAT_CSR_BASE + 0x8c)
#define HNAT_CSR34			(HNAT_CSR_BASE + 0x90)
#define HNAT_CSR35			(HNAT_CSR_BASE + 0x94)
#define HNAT_CSR36			(HNAT_CSR_BASE + 0x98)
#define HNAT_TB_STATUS			(HNAT_TABLE_BASE + 0x00)
#define HNAT_TB_CONFIG			(HNAT_TABLE_BASE + 0x04)
#define HNAT_TB_ADDRESS			(HNAT_TABLE_BASE + 0x08)
#define HNAT_TB_OPCODE			(HNAT_TABLE_BASE + 0x0c)
#define HNAT_TB_WRDATA(n)		(HNAT_TABLE_BASE + 0x10 + (n) * 4)
#define HNAT_TB_BUF_THRESH		(HNAT_TABLE_BASE + 0x50)
#define HNAT_TB_FC_CFG			(HNAT_TABLE_BASE + 0x60)
#define HNAT_TB_RFC_TIMER		(HNAT_TABLE_BASE + 0x64)
#define HNAT_TB_TFC_TIMER		(HNAT_TABLE_BASE + 0x6c)

#define HNAT_TB_CONFIG_VALUE		0x0fff0415
#define HNAT_CSR1_VALUE			0x0240004f
#define HNAT_MAX_FLOWS			1024
#define HNAT_MAX_PENDING		64
#define HNAT_NO_VLAN			0x7f
#define HNAT_NO_RESOURCE		U8_MAX
#define HNAT_NO_DIP			U16_MAX

#define HNAT_LAN_COUNT			8
#define HNAT_VLAN_COUNT		128
#define HNAT_PUBLIC_COUNT		16
#define HNAT_DIP_COUNT			512
#define HNAT_DMAC_COUNT		128
#define HNAT_RMAC_COUNT		8
#define HNAT_PPPOE_COUNT		8

#define HNAT_NAPT_HASH1_SLOTS		(512 * 2)
#define HNAT_NAPT_HASH2_SLOTS		(256 * 4)
#define HNAT_NAPT_HASH3_SLOTS		(32 * 2)
#define HNAT_NAPT_HASH_SLOTS		(HNAT_NAPT_HASH1_SLOTS + \
					 HNAT_NAPT_HASH2_SLOTS + \
					 HNAT_NAPT_HASH3_SLOTS)
#define HNAT_DIP_HASH1_SLOTS		(256 * 3)
#define HNAT_DIP_HASH2_SLOTS		(64 * 4)
#define HNAT_DIP_HASH_SLOTS		(HNAT_DIP_HASH1_SLOTS + \
					 HNAT_DIP_HASH2_SLOTS)

enum hnat_table_no {
	HNAT_INAT_HASH1 = 0,
	HNAT_INAT_HASH2 = 1,
	HNAT_INAT_HASH3 = 2,
	HNAT_ENAT_HASH1 = 3,
	HNAT_ENAT_HASH2 = 4,
	HNAT_ENAT_HASH3 = 5,
	HNAT_NAPT = 6,
	HNAT_NAPT_VALID = 7,
	HNAT_RT_PUB_NET = 8,
	HNAT_DIP_HASH1 = 16,
	HNAT_DIP_HASH2 = 17,
	HNAT_DIP = 18,
	HNAT_DIP_VALID = 19,
	HNAT_DMAC = 20,
	HNAT_PPPOE = 21,
	HNAT_ROUTER_MAC = 22,
	HNAT_VLAN = 23,
};

struct hnat_tuple {
	__be32 src;
	__be32 dst;
	__be16 sport;
	__be16 dport;
	u8 proto;
};

struct hnat_half {
	unsigned long cookie;
	struct hnat_tuple match;
	struct hnat_tuple xlate;
	int ingress_ifindex;
	int output_ifindex;
	u16 input_vlan;
	u16 output_vlan;
	u8 output_src[ETH_ALEN];
	u8 output_dst[ETH_ALEN];
	bool pppoe_push;
	u16 pppoe_session;
};

struct hnat_pending {
	struct list_head list;
	struct hnat_half half;
};

struct hnat_destroy_work {
	struct work_struct work;
	struct sf19a2890_hnat *hnat;
	unsigned long cookie;
};

struct hnat_flow {
	unsigned long cookie[2];
	unsigned long lastused;
	struct hnat_tuple private;
	__be16 public_port;
	u16 dip[2];
	u8 lan;
	u8 public;
	u8 pppoe;
	u8 hash[2];
};

struct hnat_flow_spec {
	unsigned long cookie[2];
	struct hnat_tuple private;
	__be32 public_ip;
	__be16 public_port;
	u16 lan_vlan;
	u16 wan_vlan;
	u8 client_mac[ETH_ALEN];
	u8 lan_router_mac[ETH_ALEN];
	u8 gateway_mac[ETH_ALEN];
	u8 wan_router_mac[ETH_ALEN];
	u32 lan_network;
	u8 lan_prefix;
	u8 wan_prefix;
	bool pppoe;
	u16 pppoe_session;
};

struct hnat_word {
	u32 data[5];
};

struct hnat_lan_resource {
	u32 network;
	u16 refs;
	u8 prefix;
};

struct hnat_vlan_resource {
	u16 vid;
	u16 refs;
};

struct hnat_public_resource {
	__be32 ip;
	u16 refs;
	u8 prefix;
	u8 vlan;
};

struct hnat_rmac_resource {
	u8 mac[ETH_ALEN];
	u16 refs;
};

struct hnat_dmac_resource {
	u8 mac[ETH_ALEN];
	u16 refs;
	u8 rmac;
};

struct hnat_dip_resource {
	__be32 ip;
	u16 refs;
	u8 vlan;
	u8 dmac;
	u8 hash;
};

struct hnat_pppoe_resource {
	u16 session;
	u16 refs;
};

enum hnat_hash_dir {
	HNAT_HASH_INAT,
	HNAT_HASH_ENAT,
	HNAT_HASH_DIR_COUNT,
};

enum hnat_resource_type {
	HNAT_RES_LAN,
	HNAT_RES_VLAN,
	HNAT_RES_PUBLIC,
	HNAT_RES_DIP,
	HNAT_RES_DMAC,
	HNAT_RES_RMAC,
	HNAT_RES_PPPOE,
};

struct hnat_resource_token {
	u16 index;
	u8 type;
};

struct hnat_transaction {
	struct hnat_resource_token created[12];
	u8 count;
};

struct hnat_indr_binding {
	struct list_head list;
	struct sf19a2890_hnat *hnat;
	struct net_device *netdev;
};

struct sf19a2890_hnat {
	struct device *dev;
	void __iomem *ioaddr;
	struct net_device *ndev;
	struct mutex lock;
	struct list_head pending;
	struct hnat_flow **flows;
	struct hnat_dip_resource *dip;
	struct hnat_lan_resource lan[HNAT_LAN_COUNT];
	struct hnat_vlan_resource vlan[HNAT_VLAN_COUNT];
	struct hnat_public_resource public[HNAT_PUBLIC_COUNT];
	struct hnat_dmac_resource dmac[HNAT_DMAC_COUNT];
	struct hnat_rmac_resource rmac[HNAT_RMAC_COUNT];
	struct hnat_pppoe_resource pppoe[HNAT_PPPOE_COUNT];
	unsigned long napt_hash_used[HNAT_HASH_DIR_COUNT]
		[BITS_TO_LONGS(HNAT_NAPT_HASH_SLOTS)];
	unsigned long dip_hash_used[BITS_TO_LONGS(HNAT_DIP_HASH_SLOTS)];
	struct list_head block_cb_list;
	struct list_head indr_bindings;
	struct workqueue_struct *destroy_wq;
	bool degraded;
	unsigned int active_count;
	unsigned int pending_count;
	unsigned int reset_count;
	unsigned int table_errors;
	unsigned int parse_errors;
	unsigned int unsupported_action;
	unsigned int invalid_l2;
	struct dentry *debugfs;
};

static int hnat_table_wait(struct sf19a2890_hnat *hnat)
{
	u32 val;

	return readl_poll_timeout_atomic(hnat->ioaddr + HNAT_TB_STATUS, val,
					 !(val & BIT(0)), 1, 10000);
}

static int hnat_table_write(struct sf19a2890_hnat *hnat, u8 table, u16 index,
			    const struct hnat_word *word)
{
	int i, ret;

	ret = hnat_table_wait(hnat);
	if (ret)
		return ret;
	writel(((u32)table << 16) | index, hnat->ioaddr + HNAT_TB_ADDRESS);
	for (i = 0; i < 5; i++)
		writel(word->data[i], hnat->ioaddr + HNAT_TB_WRDATA(i));
	writel(1, hnat->ioaddr + HNAT_TB_OPCODE);
	return hnat_table_wait(hnat);
}

static u16 hnat_crc16(const u8 *data, size_t len, u16 poly)
{
	u16 crc = 0;
	int bit;

	while (len--) {
		crc ^= *data++ << 8;
		for (bit = 0; bit < 8; bit++)
			crc = crc & 0x8000 ? (crc << 1) ^ poly : crc << 1;
	}
	return crc;
}

static u32 hnat_prefix_mask(u8 prefix)
{
	return prefix ? ~0U << (32 - prefix) : 0;
}

static u8 hnat_public_prefix(u8 prefix)
{
	/* The public-network table has a five-bit prefix field. */
	return min_t(u8, prefix, 31);
}

static bool hnat_subnets_overlap(u32 a, u8 a_prefix, u32 b, u8 b_prefix)
{
	u32 mask = hnat_prefix_mask(min(a_prefix, b_prefix));

	return !((a ^ b) & mask);
}

static u8 hnat_hash_location(u8 level, u8 slot)
{
	return level << 3 | slot;
}

static u8 hnat_hash_level(u8 location)
{
	return location >> 3;
}

static u8 hnat_hash_slot(u8 location)
{
	return location & 7;
}

static unsigned int hnat_napt_hash_bit(u8 level, u16 key, u8 slot)
{
	if (!level)
		return key * 2 + slot;
	if (level == 1)
		return HNAT_NAPT_HASH1_SLOTS + key * 4 + slot;
	return HNAT_NAPT_HASH1_SLOTS + HNAT_NAPT_HASH2_SLOTS +
		key * 2 + slot;
}

static unsigned int hnat_dip_hash_bit(u8 level, u16 key, u8 slot)
{
	if (!level)
		return key * 3 + (slot == 3 ? 2 : slot);
	return HNAT_DIP_HASH1_SLOTS + key * 4 + slot;
}

static int hnat_ref_get(u16 *refs)
{
	if (*refs == U16_MAX)
		return -EOVERFLOW;
	(*refs)++;
	return 0;
}

static void hnat_txn_created(struct hnat_transaction *txn, u8 type, u16 index)
{
	if (WARN_ON(txn->count == ARRAY_SIZE(txn->created)))
		return;
	txn->created[txn->count].type = type;
	txn->created[txn->count++].index = index;
}

static bool hnat_vlan_matches(struct sf19a2890_hnat *hnat, u8 index, u16 vid)
{
	if (!vid)
		return index == HNAT_NO_VLAN;
	return index < HNAT_NO_VLAN && hnat->vlan[index].refs &&
		hnat->vlan[index].vid == vid;
}

static bool hnat_rmac_matches(struct sf19a2890_hnat *hnat, u8 index,
			      const u8 *mac)
{
	return index < HNAT_RMAC_COUNT && hnat->rmac[index].refs &&
		ether_addr_equal(hnat->rmac[index].mac, mac);
}

static bool hnat_dmac_matches(struct sf19a2890_hnat *hnat, u8 index,
			      const u8 *dmac, const u8 *rmac)
{
	struct hnat_dmac_resource *res;

	if (index >= HNAT_DMAC_COUNT)
		return false;
	res = &hnat->dmac[index];
	return res->refs && ether_addr_equal(res->mac, dmac) &&
		hnat_rmac_matches(hnat, res->rmac, rmac);
}

static int hnat_vlan_get(struct sf19a2890_hnat *hnat, u16 vid,
			 struct hnat_transaction *txn)
{
	int i, free = -1, ret;

	if (!vid)
		return HNAT_NO_VLAN;
	for (i = 0; i < HNAT_NO_VLAN; i++) {
		if (!hnat->vlan[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (hnat->vlan[i].vid != vid)
			continue;
		ret = hnat_ref_get(&hnat->vlan[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	hnat->vlan[free].vid = vid;
	hnat->vlan[free].refs = 1;
	hnat_txn_created(txn, HNAT_RES_VLAN, free);
	return free;
}

static void hnat_vlan_put(struct sf19a2890_hnat *hnat, u8 index)
{
	if (index == HNAT_NO_VLAN)
		return;
	if (WARN_ON(index >= HNAT_NO_VLAN || !hnat->vlan[index].refs))
		return;
	hnat->vlan[index].refs--;
}

static int hnat_rmac_get(struct sf19a2890_hnat *hnat, const u8 *mac,
			 struct hnat_transaction *txn)
{
	int i, free = -1, ret;

	for (i = 0; i < HNAT_RMAC_COUNT; i++) {
		if (!hnat->rmac[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (!ether_addr_equal(hnat->rmac[i].mac, mac))
			continue;
		ret = hnat_ref_get(&hnat->rmac[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	ether_addr_copy(hnat->rmac[free].mac, mac);
	hnat->rmac[free].refs = 1;
	hnat_txn_created(txn, HNAT_RES_RMAC, free);
	return free;
}

static void hnat_rmac_put(struct sf19a2890_hnat *hnat, u8 index)
{
	if (WARN_ON(index >= HNAT_RMAC_COUNT || !hnat->rmac[index].refs))
		return;
	hnat->rmac[index].refs--;
}

static int hnat_dmac_get(struct sf19a2890_hnat *hnat, const u8 *dmac,
			 const u8 *rmac, struct hnat_transaction *txn)
{
	int i, free = -1, rmac_index, ret;

	for (i = 0; i < HNAT_DMAC_COUNT; i++) {
		if (!hnat->dmac[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (!hnat_dmac_matches(hnat, i, dmac, rmac))
			continue;
		ret = hnat_ref_get(&hnat->dmac[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	rmac_index = hnat_rmac_get(hnat, rmac, txn);
	if (rmac_index < 0)
		return rmac_index;
	ether_addr_copy(hnat->dmac[free].mac, dmac);
	hnat->dmac[free].rmac = rmac_index;
	hnat->dmac[free].refs = 1;
	hnat_txn_created(txn, HNAT_RES_DMAC, free);
	return free;
}

static void hnat_dmac_put(struct sf19a2890_hnat *hnat, u8 index)
{
	struct hnat_dmac_resource *res;

	if (WARN_ON(index >= HNAT_DMAC_COUNT || !hnat->dmac[index].refs))
		return;
	res = &hnat->dmac[index];
	if (--res->refs)
		return;
	hnat_rmac_put(hnat, res->rmac);
}

static void hnat_dip_keys(const struct hnat_dip_resource *res, u16 key[2])
{
	u8 data[5];
	u16 crc;
	int i;

	memcpy(data, &res->ip, sizeof(res->ip));
	data[4] = res->vlan;
	/* Right-carry one bit across IP+7-bit VLAN, as required by hardware. */
	for (i = 3; i >= 0; i--) {
		data[i + 1] &= 0x7f;
		data[i + 1] |= (data[i] & 1) << 7;
		data[i] >>= 1;
	}
	crc = hnat_crc16(data, sizeof(data), 0x1021);
	key[0] = crc & 0xff;
	key[1] = (crc & 0xfc00) >> 10;
}

static int hnat_dip_hash_reserve(struct sf19a2890_hnat *hnat,
				 struct hnat_dip_resource *res)
{
	static const u8 level0_slots[] = { 0, 1, 3 };
	u16 key[2];
	unsigned int bit;
	int i;

	hnat_dip_keys(res, key);
	for (i = 0; i < ARRAY_SIZE(level0_slots); i++) {
		bit = hnat_dip_hash_bit(0, key[0], level0_slots[i]);
		if (!test_and_set_bit(bit, hnat->dip_hash_used)) {
			res->hash = hnat_hash_location(0, level0_slots[i]);
			return 0;
		}
	}
	for (i = 0; i < 4; i++) {
		bit = hnat_dip_hash_bit(1, key[1], i);
		if (!test_and_set_bit(bit, hnat->dip_hash_used)) {
			res->hash = hnat_hash_location(1, i);
			return 0;
		}
	}
	return -ENOSPC;
}

static void hnat_dip_hash_release(struct sf19a2890_hnat *hnat,
				  struct hnat_dip_resource *res)
{
	u8 level = hnat_hash_level(res->hash);
	u16 key[2];

	hnat_dip_keys(res, key);
	clear_bit(hnat_dip_hash_bit(level, key[level],
				    hnat_hash_slot(res->hash)),
		  hnat->dip_hash_used);
}

static bool hnat_dip_matches(struct sf19a2890_hnat *hnat, u16 index,
			     __be32 ip, u16 vlan, const u8 *dmac,
			     const u8 *rmac)
{
	struct hnat_dip_resource *res;

	if (index >= HNAT_DIP_COUNT)
		return false;
	res = &hnat->dip[index];
	return res->refs && res->ip == ip &&
		hnat_vlan_matches(hnat, res->vlan, vlan) &&
		hnat_dmac_matches(hnat, res->dmac, dmac, rmac);
}

static int hnat_dip_get(struct sf19a2890_hnat *hnat, __be32 ip, u16 vlan,
			const u8 *dmac, const u8 *rmac,
			struct hnat_transaction *txn)
{
	struct hnat_dip_resource *res;
	int i, free = -1, vlan_index, dmac_index, ret;

	for (i = 0; i < HNAT_DIP_COUNT; i++) {
		if (!hnat->dip[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (!hnat_dip_matches(hnat, i, ip, vlan, dmac, rmac))
			continue;
		ret = hnat_ref_get(&hnat->dip[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	vlan_index = hnat_vlan_get(hnat, vlan, txn);
	if (vlan_index < 0)
		return vlan_index;
	dmac_index = hnat_dmac_get(hnat, dmac, rmac, txn);
	if (dmac_index < 0) {
		hnat_vlan_put(hnat, vlan_index);
		return dmac_index;
	}
	res = &hnat->dip[free];
	res->ip = ip;
	res->vlan = vlan_index;
	res->dmac = dmac_index;
	res->refs = 1;
	ret = hnat_dip_hash_reserve(hnat, res);
	if (ret) {
		res->refs = 0;
		hnat_dmac_put(hnat, dmac_index);
		hnat_vlan_put(hnat, vlan_index);
		return ret;
	}
	hnat_txn_created(txn, HNAT_RES_DIP, free);
	return free;
}

static void hnat_dip_put(struct sf19a2890_hnat *hnat, u16 index,
			 u16 freed[2], u8 *freed_count)
{
	struct hnat_dip_resource *res;

	if (WARN_ON(index >= HNAT_DIP_COUNT || !hnat->dip[index].refs))
		return;
	res = &hnat->dip[index];
	if (--res->refs)
		return;
	hnat_dip_hash_release(hnat, res);
	if (freed && !WARN_ON(*freed_count == 2))
		freed[(*freed_count)++] = index;
	hnat_dmac_put(hnat, res->dmac);
	hnat_vlan_put(hnat, res->vlan);
}

static int hnat_lan_get(struct sf19a2890_hnat *hnat, u32 network, u8 prefix,
			struct hnat_transaction *txn)
{
	u32 wan_network;
	int i, free = -1, ret;

	for (i = 0; i < HNAT_LAN_COUNT; i++) {
		if (!hnat->lan[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (hnat->lan[i].network != network ||
		    hnat->lan[i].prefix != prefix)
			continue;
		ret = hnat_ref_get(&hnat->lan[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	for (i = 0; i < HNAT_PUBLIC_COUNT; i++) {
		if (!hnat->public[i].refs)
			continue;
		wan_network = ntohl(hnat->public[i].ip) &
			hnat_prefix_mask(hnat->public[i].prefix);
		if (hnat_subnets_overlap(network, prefix, wan_network,
					 hnat->public[i].prefix)) {
			__be32 lan_ip = htonl(network);
			__be32 wan_ip = htonl(wan_network);

			dev_warn_ratelimited(hnat->dev,
					     "reject overlapping HNAT LAN %pI4/%u and WAN %pI4/%u\n",
					     &lan_ip, prefix, &wan_ip,
					     hnat->public[i].prefix);
			return -EOPNOTSUPP;
		}
	}
	hnat->lan[free].network = network;
	hnat->lan[free].prefix = prefix;
	hnat->lan[free].refs = 1;
	hnat_txn_created(txn, HNAT_RES_LAN, free);
	return free;
}

static void hnat_lan_put(struct sf19a2890_hnat *hnat, u8 index)
{
	if (WARN_ON(index >= HNAT_LAN_COUNT || !hnat->lan[index].refs))
		return;
	hnat->lan[index].refs--;
}

static int hnat_public_get(struct sf19a2890_hnat *hnat, __be32 ip, u8 prefix,
			   u16 vlan, struct hnat_transaction *txn)
{
	u32 network;
	int i, free = -1, vlan_index, ret;

	prefix = hnat_public_prefix(prefix);
	for (i = 0; i < HNAT_PUBLIC_COUNT; i++) {
		if (!hnat->public[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (hnat->public[i].ip != ip ||
		    hnat->public[i].prefix != prefix ||
		    !hnat_vlan_matches(hnat, hnat->public[i].vlan, vlan))
			continue;
		ret = hnat_ref_get(&hnat->public[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	network = ntohl(ip) & hnat_prefix_mask(prefix);
	for (i = 0; i < HNAT_LAN_COUNT; i++) {
		if (!hnat->lan[i].refs)
			continue;
		if (hnat_subnets_overlap(hnat->lan[i].network,
					 hnat->lan[i].prefix, network, prefix)) {
			__be32 lan_ip = htonl(hnat->lan[i].network);
			__be32 wan_ip = htonl(network);

			dev_warn_ratelimited(hnat->dev,
					     "reject overlapping HNAT LAN %pI4/%u and WAN %pI4/%u\n",
					     &lan_ip, hnat->lan[i].prefix,
					     &wan_ip, prefix);
			return -EOPNOTSUPP;
		}
	}
	vlan_index = hnat_vlan_get(hnat, vlan, txn);
	if (vlan_index < 0)
		return vlan_index;
	hnat->public[free].ip = ip;
	hnat->public[free].prefix = prefix;
	hnat->public[free].vlan = vlan_index;
	hnat->public[free].refs = 1;
	hnat_txn_created(txn, HNAT_RES_PUBLIC, free);
	return free;
}

static void hnat_public_put(struct sf19a2890_hnat *hnat, u8 index)
{
	struct hnat_public_resource *res;

	if (WARN_ON(index >= HNAT_PUBLIC_COUNT || !hnat->public[index].refs))
		return;
	res = &hnat->public[index];
	if (--res->refs)
		return;
	hnat_vlan_put(hnat, res->vlan);
}

static int hnat_pppoe_get(struct sf19a2890_hnat *hnat, u16 session,
			  struct hnat_transaction *txn)
{
	int i, free = -1, ret;

	for (i = 0; i < HNAT_PPPOE_COUNT; i++) {
		if (!hnat->pppoe[i].refs) {
			if (free < 0)
				free = i;
			continue;
		}
		if (hnat->pppoe[i].session != session)
			continue;
		ret = hnat_ref_get(&hnat->pppoe[i].refs);
		return ret ? ret : i;
	}
	if (free < 0)
		return -ENOSPC;
	hnat->pppoe[free].session = session;
	hnat->pppoe[free].refs = 1;
	hnat_txn_created(txn, HNAT_RES_PPPOE, free);
	return free;
}

static void hnat_pppoe_put(struct sf19a2890_hnat *hnat, u8 index)
{
	if (index == HNAT_NO_RESOURCE)
		return;
	if (WARN_ON(index >= HNAT_PPPOE_COUNT || !hnat->pppoe[index].refs))
		return;
	hnat->pppoe[index].refs--;
}

static void hnat_napt_keys(struct sf19a2890_hnat *hnat,
			   const struct hnat_flow *flow, bool inat,
			   u16 key[3])
{
	u8 data[13] = {};
	u16 crc1, crc2;

	data[0] = flow->private.proto == IPPROTO_UDP;
	if (!inat) {
		memcpy(data + 1, &flow->private.sport, 2);
		memcpy(data + 3, &flow->private.src, 4);
		memcpy(data + 7, &flow->private.dport, 2);
		memcpy(data + 9, &flow->private.dst, 4);
	} else {
		memcpy(data + 1, &flow->private.dport, 2);
		memcpy(data + 3, &flow->private.dst, 4);
		memcpy(data + 7, &flow->public_port, 2);
		memcpy(data + 9, &hnat->public[flow->public].ip, 4);
	}
	crc1 = hnat_crc16(data, sizeof(data), 0x1021);
	crc2 = hnat_crc16(data, sizeof(data), 0x8005);
	key[0] = (crc1 & 0xff80) >> 7;
	key[1] = crc1 & 0xff;
	key[2] = (crc2 & 0x1f0) >> 4;
}

static int hnat_napt_hash_reserve(struct sf19a2890_hnat *hnat,
				  struct hnat_flow *flow,
				  enum hnat_hash_dir dir)
{
	static const u8 slots[] = { 2, 4, 2 };
	u16 key[3];
	unsigned int bit;
	int level, slot;

	hnat_napt_keys(hnat, flow, dir == HNAT_HASH_INAT, key);
	for (level = 0; level < 3; level++) {
		for (slot = 0; slot < slots[level]; slot++) {
			bit = hnat_napt_hash_bit(level, key[level], slot);
			if (test_and_set_bit(bit, hnat->napt_hash_used[dir]))
				continue;
			flow->hash[dir] = hnat_hash_location(level, slot);
			return 0;
		}
	}
	return -ENOSPC;
}

static void hnat_napt_hash_release(struct sf19a2890_hnat *hnat,
				   struct hnat_flow *flow,
				   enum hnat_hash_dir dir)
{
	u8 level = hnat_hash_level(flow->hash[dir]);
	u16 key[3];

	if (flow->hash[dir] == HNAT_NO_RESOURCE)
		return;
	hnat_napt_keys(hnat, flow, dir == HNAT_HASH_INAT, key);
	clear_bit(hnat_napt_hash_bit(level, key[level],
				     hnat_hash_slot(flow->hash[dir])),
		  hnat->napt_hash_used[dir]);
	flow->hash[dir] = HNAT_NO_RESOURCE;
}

static void hnat_napt_hash_insert(struct hnat_word *word, u8 level, u8 slot,
				  u16 napt)
{
	if (level != 1) {
		word->data[0] |= napt << (slot * 10);
		word->data[0] |= BIT(20 + slot);
		return;
	}
	if (slot < 3)
		word->data[0] |= napt << (slot * 10);
	else {
		word->data[0] |= (napt & 3) << 30;
		word->data[1] |= (napt & 0x3fc) >> 2;
	}
	word->data[1] |= BIT(8 + slot);
}

static void hnat_napt_hash_word(struct sf19a2890_hnat *hnat,
				enum hnat_hash_dir dir, u8 level, u16 bucket,
				const struct hnat_flow *candidate,
				u16 candidate_index, struct hnat_word *word)
{
	struct hnat_flow *flow;
	u16 key[3];
	int i;

	memset(word, 0, sizeof(*word));
	for (i = 0; i < HNAT_MAX_FLOWS; i++) {
		flow = hnat->flows[i];
		if (!flow || hnat_hash_level(flow->hash[dir]) != level)
			continue;
		hnat_napt_keys(hnat, flow, dir == HNAT_HASH_INAT, key);
		if (key[level] == bucket)
			hnat_napt_hash_insert(word, level,
					      hnat_hash_slot(flow->hash[dir]), i);
	}
	if (!candidate || hnat_hash_level(candidate->hash[dir]) != level)
		return;
	hnat_napt_keys(hnat, candidate, dir == HNAT_HASH_INAT, key);
	if (key[level] == bucket)
		hnat_napt_hash_insert(word, level,
				      hnat_hash_slot(candidate->hash[dir]),
				      candidate_index);
}

static void hnat_dip_hash_insert(struct hnat_word *word, u8 slot, u16 dip)
{
	if (slot < 3)
		word->data[0] |= dip << (slot * 9);
	else {
		word->data[0] |= (dip & 0x1f) << 27;
		word->data[1] |= (dip & 0x1e0) >> 5;
	}
	word->data[1] |= BIT(4 + slot);
}

static void hnat_dip_hash_word(struct sf19a2890_hnat *hnat, u8 level,
			       u16 bucket, struct hnat_word *word)
{
	struct hnat_dip_resource *res;
	u16 key[2];
	int i;

	memset(word, 0, sizeof(*word));
	for (i = 0; i < HNAT_DIP_COUNT; i++) {
		res = &hnat->dip[i];
		if (!res->refs || hnat_hash_level(res->hash) != level)
			continue;
		hnat_dip_keys(res, key);
		if (key[level] == bucket)
			hnat_dip_hash_insert(word, hnat_hash_slot(res->hash), i);
	}
}

static void hnat_write_config_csrs(struct sf19a2890_hnat *hnat)
{
	writel(0x64, hnat->ioaddr + HNAT_CSR(4));
	writel(0x400000, hnat->ioaddr + HNAT_CSR(3));
	writel(HNAT_TB_CONFIG_VALUE, hnat->ioaddr + HNAT_TB_CONFIG);
	writel(0x1500, hnat->ioaddr + HNAT_TB_RFC_TIMER);
	writel(0x1500, hnat->ioaddr + HNAT_TB_TFC_TIMER);
	writel(3, hnat->ioaddr + HNAT_TB_FC_CFG);
	writel(0, hnat->ioaddr + HNAT_TB_FC_CFG);
	writel(0x20f020f, hnat->ioaddr + HNAT_TB_BUF_THRESH);
	writel(0x165a0bc0, hnat->ioaddr + HNAT_CSR33);
	writel(0x5f5e10, hnat->ioaddr + HNAT_CSR34);
	writel(0xffffffff, hnat->ioaddr + HNAT_CSR35);
	writel(0x47868c0, hnat->ioaddr + HNAT_CSR36);
}

static void hnat_write_lan_csrs(struct sf19a2890_hnat *hnat)
{
	u32 masks[2] = {};
	int i;

	for (i = 0; i < HNAT_LAN_COUNT; i++) {
		u32 value = 0;

		if (hnat->lan[i].refs) {
			value = hnat->lan[i].network;
			masks[i / 4] |= ((32 - hnat->lan[i].prefix) | 0x20) <<
					(i % 4) * 8;
		}
		writel(value, hnat->ioaddr + HNAT_CSR_LAN(i));
	}
	writel(masks[0], hnat->ioaddr + HNAT_CSR_LAN_MASK0);
	writel(masks[1], hnat->ioaddr + HNAT_CSR_LAN_MASK1);
	/* CSR2 bit 0 commits changed LAN subnet comparator contents. */
	writel(readl(hnat->ioaddr + HNAT_CSR(2)) & ~BIT(0),
	       hnat->ioaddr + HNAT_CSR(2));
	writel(readl(hnat->ioaddr + HNAT_CSR(2)) | BIT(0),
	       hnat->ioaddr + HNAT_CSR(2));
}

static void hnat_napt_word(struct sf19a2890_hnat *hnat,
			   const struct hnat_flow *flow, struct hnat_word *word)
{
	u32 sip = (__force u32)flow->private.src;
	u8 lan_vlan = hnat->dip[flow->dip[0]].vlan;

	memset(word, 0, sizeof(*word));
	word->data[0] = (__force u32)flow->private.dst;
	word->data[1] = (sip & 0xffff) << 16 |
		(__force u16)flow->private.dport;
	word->data[2] = (__force u16)flow->private.sport << 16 |
		(sip >> 16 & 0xffff);
	word->data[3] = (flow->private.proto == IPPROTO_UDP) << 27 |
		lan_vlan << 20 | (__force u16)flow->public_port << 4 |
		flow->public;
	if (flow->pppoe != HNAT_NO_RESOURCE) {
		word->data[3] |= BIT(29) | (flow->pppoe & 3) << 30;
		word->data[4] = (flow->pppoe & 4) >> 2;
	}
}

static void hnat_napt_valid_word(struct sf19a2890_hnat *hnat, u16 group,
				 const struct hnat_flow *candidate,
				 u16 candidate_index, struct hnat_word *word)
{
	int i, start = group * 32;

	memset(word, 0, sizeof(*word));
	for (i = 0; i < 32; i++)
		if (hnat->flows[start + i])
			word->data[0] |= BIT(i);
	if (candidate && candidate_index / 32 == group)
		word->data[0] |= BIT(candidate_index % 32);
}

static void hnat_dip_valid_word(struct sf19a2890_hnat *hnat, u16 group,
				struct hnat_word *word)
{
	int i, start = group * 32;

	memset(word, 0, sizeof(*word));
	for (i = 0; i < 32; i++)
		if (hnat->dip[start + i].refs)
			word->data[0] |= BIT(i);
}

static int hnat_write_resource(struct sf19a2890_hnat *hnat, u8 type,
			       u16 index)
{
	struct hnat_word word = {};

	switch (type) {
	case HNAT_RES_VLAN:
		if (!hnat->vlan[index].refs)
			return 0;
		word.data[0] = hnat->vlan[index].vid;
		return hnat_table_write(hnat, HNAT_VLAN, index, &word);
	case HNAT_RES_PUBLIC:
		if (!hnat->public[index].refs)
			return 0;
		word.data[0] = (__force u32)hnat->public[index].ip;
		word.data[1] = hnat->public[index].prefix |
			hnat->public[index].vlan << 5;
		return hnat_table_write(hnat, HNAT_RT_PUB_NET, index, &word);
	case HNAT_RES_DIP:
		if (!hnat->dip[index].refs)
			return 0;
		word.data[0] = (__force u32)hnat->dip[index].ip;
		word.data[1] = hnat->dip[index].vlan << 7 |
			hnat->dip[index].dmac;
		return hnat_table_write(hnat, HNAT_DIP, index, &word);
	case HNAT_RES_DMAC:
		if (!hnat->dmac[index].refs)
			return 0;
		word.data[0] = get_unaligned_le32(hnat->dmac[index].mac);
		word.data[1] = get_unaligned_le16(hnat->dmac[index].mac + 4) |
			hnat->dmac[index].rmac << 16;
		return hnat_table_write(hnat, HNAT_DMAC, index, &word);
	case HNAT_RES_RMAC:
		if (!hnat->rmac[index].refs)
			return 0;
		word.data[0] = get_unaligned_le32(hnat->rmac[index].mac);
		word.data[1] = get_unaligned_le16(hnat->rmac[index].mac + 4);
		return hnat_table_write(hnat, HNAT_ROUTER_MAC, index, &word);
	case HNAT_RES_PPPOE:
		if (!hnat->pppoe[index].refs)
			return 0;
		word.data[0] = 0x21;
		word.data[1] = 0x11000000 | hnat->pppoe[index].session;
		return hnat_table_write(hnat, HNAT_PPPOE, index, &word);
	case HNAT_RES_LAN:
		return 0;
	default:
		return -EINVAL;
	}
}

static int hnat_write_dip_hash_bucket(struct sf19a2890_hnat *hnat, u8 level,
				      u16 key)
{
	struct hnat_word word;

	hnat_dip_hash_word(hnat, level, key, &word);
	return hnat_table_write(hnat, HNAT_DIP_HASH1 + level, key, &word);
}

static int hnat_write_napt_hash_bucket(struct sf19a2890_hnat *hnat,
				       enum hnat_hash_dir dir, u8 level,
				       u16 key,
				       const struct hnat_flow *candidate,
				       u16 candidate_index)
{
	struct hnat_word word;
	u8 table = dir == HNAT_HASH_INAT ? HNAT_INAT_HASH1 : HNAT_ENAT_HASH1;

	hnat_napt_hash_word(hnat, dir, level, key, candidate, candidate_index,
			     &word);
	return hnat_table_write(hnat, table + level, key, &word);
}

static int hnat_program_created(struct sf19a2890_hnat *hnat,
				struct hnat_transaction *txn)
{
	struct hnat_dip_resource *dip;
	struct hnat_word word;
	u16 key[2];
	int i, ret;

	for (i = 0; i < txn->count; i++) {
		ret = hnat_write_resource(hnat, txn->created[i].type,
					  txn->created[i].index);
		if (ret)
			return ret;
	}
	/* All DIP payloads must exist before a shared hash/valid word can make
	 * any of them visible.
	 */
	for (i = 0; i < txn->count; i++) {
		if (txn->created[i].type != HNAT_RES_DIP)
			continue;
		dip = &hnat->dip[txn->created[i].index];
		if (!dip->refs)
			continue;
		hnat_dip_keys(dip, key);
		ret = hnat_write_dip_hash_bucket(hnat,
					 hnat_hash_level(dip->hash),
					 key[hnat_hash_level(dip->hash)]);
		if (ret)
			return ret;
	}
	for (i = 0; i < txn->count; i++) {
		if (txn->created[i].type != HNAT_RES_DIP)
			continue;
		hnat_dip_valid_word(hnat, txn->created[i].index / 32, &word);
		ret = hnat_table_write(hnat, HNAT_DIP_VALID,
				       txn->created[i].index / 32, &word);
		if (ret)
			return ret;
	}
	hnat_write_lan_csrs(hnat);
	return 0;
}

static bool hnat_bitmap_bucket_used(const unsigned long *bitmap,
				    unsigned int first, unsigned int count)
{
	return find_next_bit(bitmap, first + count, first) < first + count;
}

static int hnat_replay(struct sf19a2890_hnat *hnat)
{
	static const u16 napt_buckets[] = { 512, 256, 32 };
	static const u8 napt_slots[] = { 2, 4, 2 };
	static const u16 napt_offsets[] = {
		0, HNAT_NAPT_HASH1_SLOTS,
		HNAT_NAPT_HASH1_SLOTS + HNAT_NAPT_HASH2_SLOTS,
	};
	static const u16 dip_buckets[] = { 256, 64 };
	static const u8 dip_slots[] = { 3, 4 };
	static const u16 dip_offsets[] = { 0, HNAT_DIP_HASH1_SLOTS };
	struct hnat_word word;
	int dir, level, i, ret;

	/* DWMAC reset cleared every table, so only live metadata is replayed. */
	writel(HNAT_CSR1_VALUE, hnat->ioaddr + HNAT_CSR(1));
	hnat_write_config_csrs(hnat);
	hnat_write_lan_csrs(hnat);
	for (i = 0; i < HNAT_VLAN_COUNT; i++) {
		ret = hnat_write_resource(hnat, HNAT_RES_VLAN, i);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_RMAC_COUNT; i++) {
		ret = hnat_write_resource(hnat, HNAT_RES_RMAC, i);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_DMAC_COUNT; i++) {
		ret = hnat_write_resource(hnat, HNAT_RES_DMAC, i);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_DIP_COUNT; i++) {
		ret = hnat_write_resource(hnat, HNAT_RES_DIP, i);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_PUBLIC_COUNT; i++) {
		ret = hnat_write_resource(hnat, HNAT_RES_PUBLIC, i);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_PPPOE_COUNT; i++) {
		ret = hnat_write_resource(hnat, HNAT_RES_PPPOE, i);
		if (ret)
			return ret;
	}
	for (level = 0; level < 2; level++)
		for (i = 0; i < dip_buckets[level]; i++) {
			if (!hnat_bitmap_bucket_used(hnat->dip_hash_used,
					dip_offsets[level] + i * dip_slots[level],
					dip_slots[level]))
				continue;
			ret = hnat_write_dip_hash_bucket(hnat, level, i);
			if (ret)
				return ret;
		}
	for (i = 0; i < HNAT_DIP_COUNT / 32; i++) {
		hnat_dip_valid_word(hnat, i, &word);
		if (!word.data[0])
			continue;
		ret = hnat_table_write(hnat, HNAT_DIP_VALID, i, &word);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_MAX_FLOWS; i++) {
		if (!hnat->flows[i])
			continue;
		hnat_napt_word(hnat, hnat->flows[i], &word);
		ret = hnat_table_write(hnat, HNAT_NAPT, i, &word);
		if (ret)
			return ret;
	}
	for (dir = 0; dir < HNAT_HASH_DIR_COUNT; dir++)
		for (level = 0; level < 3; level++)
			for (i = 0; i < napt_buckets[level]; i++) {
				if (!hnat_bitmap_bucket_used(
					    hnat->napt_hash_used[dir],
					    napt_offsets[level] +
					    i * napt_slots[level],
					    napt_slots[level]))
					continue;
				ret = hnat_write_napt_hash_bucket(hnat, dir,
							  level, i, NULL, 0);
				if (ret)
					return ret;
			}
	for (i = 0; i < HNAT_MAX_FLOWS / 32; i++) {
		hnat_napt_valid_word(hnat, i, NULL, 0, &word);
		if (!word.data[0])
			continue;
		ret = hnat_table_write(hnat, HNAT_NAPT_VALID, i, &word);
		if (ret)
			return ret;
	}
	return 0;
}

static void hnat_degrade(struct sf19a2890_hnat *hnat, int error)
{
	if (!hnat->degraded)
		dev_err(hnat->dev, "HNAT table programming failed: %d; disabling offload\n",
			error);
	hnat->table_errors++;
	hnat->degraded = true;
	writel(0, hnat->ioaddr + HNAT_CSR(1));
}

static bool hnat_tuple_reverse(const struct hnat_tuple *a,
			       const struct hnat_tuple *b)
{
	return a->src == b->dst && a->dst == b->src &&
	       a->sport == b->dport && a->dport == b->sport &&
	       a->proto == b->proto;
}

static void hnat_mangle_eth(const struct flow_action_entry *act, u8 *eth)
{
	void *dst = eth + act->mangle.offset;
	const void *src = &act->mangle.val;

	if (act->mangle.offset > 8)
		return;
	if (act->mangle.mask == 0xffff) {
		src += 2;
		dst += 2;
	}
	memcpy(dst, src, act->mangle.mask ? 2 : 4);
}

static int hnat_mangle_ports(const struct flow_action_entry *act,
			     struct hnat_tuple *tuple)
{
	u32 val = ntohl(act->mangle.val);

	switch (act->mangle.offset) {
	case 0:
		if (act->mangle.mask == ~htonl(0xffff))
			tuple->dport = cpu_to_be16(val);
		else
			tuple->sport = cpu_to_be16(val >> 16);
		break;
	case 2:
		tuple->dport = cpu_to_be16(val);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int hnat_dev_vlan(struct net_device *dev, u16 *vid)
{
	struct net_device *lower;
	struct list_head *iter;
	u16 found = 0;
	bool have_lower = false;
	int ret;

	if (!dev) {
		*vid = 0;
		return 0;
	}
	if (is_vlan_dev(dev)) {
		*vid = vlan_dev_vlan_id(dev);
		return 0;
	}

	/* A flow redirect may name a bridge rather than its VLAN lower device. */
	netdev_for_each_lower_dev(dev, lower, iter) {
		u16 lower_vid;

		ret = hnat_dev_vlan(lower, &lower_vid);
		if (ret)
			return ret;
		if (have_lower && lower_vid != found)
			return -EOPNOTSUPP;
		found = lower_vid;
		have_lower = true;
	}
	*vid = found;
	return 0;
}

static int hnat_parse_half(struct sf19a2890_hnat *hnat,
			   struct flow_cls_offload *cls, struct hnat_half *half)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_action_entry *act;
	struct flow_match_ipv4_addrs addrs;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ports ports;
	struct flow_match_meta meta;
	struct net_device *idev = NULL;
	u8 eth[ETH_HLEN] = {};
	bool vlan_action = false;
	int i, ret;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS))
		return -EOPNOTSUPP;
	flow_rule_match_meta(rule, &meta);
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	flow_rule_match_ipv4_addrs(rule, &addrs);
	flow_rule_match_ports(rule, &ports);
	if (control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
	    (basic.key->ip_proto != IPPROTO_TCP &&
	     basic.key->ip_proto != IPPROTO_UDP))
		return -EOPNOTSUPP;

	half->cookie = cls->cookie;
	half->match.src = addrs.key->src;
	half->match.dst = addrs.key->dst;
	half->match.sport = ports.key->src;
	half->match.dport = ports.key->dst;
	half->match.proto = basic.key->ip_proto;
	half->xlate = half->match;
	half->ingress_ifindex = meta.key->ingress_ifindex;
	idev = __dev_get_by_index(&init_net, half->ingress_ifindex);
	ret = hnat_dev_vlan(idev, &half->input_vlan);
	if (ret)
		return ret;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_vlan(rule, &vlan);
		if (vlan.key->vlan_tpid != htons(ETH_P_8021Q))
			return -EOPNOTSUPP;
		half->input_vlan = vlan.key->vlan_id;
	}

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			switch (act->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
				hnat_mangle_eth(act, eth);
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
				if (act->mangle.offset == offsetof(struct iphdr, saddr))
					memcpy(&half->xlate.src, &act->mangle.val, 4);
				else if (act->mangle.offset == offsetof(struct iphdr, daddr))
					memcpy(&half->xlate.dst, &act->mangle.val, 4);
				else
					return -EOPNOTSUPP;
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
				ret = hnat_mangle_ports(act, &half->xlate);
				if (ret)
					return ret;
				break;
			default:
				return -EOPNOTSUPP;
			}
			break;
		case FLOW_ACTION_REDIRECT:
			half->output_ifindex = act->dev->ifindex;
			if (!vlan_action) {
				ret = hnat_dev_vlan(act->dev,
						    &half->output_vlan);
				if (ret)
					return ret;
			}
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (act->vlan.proto != htons(ETH_P_8021Q))
				return -EOPNOTSUPP;
			half->output_vlan = act->vlan.vid;
			vlan_action = true;
			break;
		case FLOW_ACTION_VLAN_POP:
			half->output_vlan = 0;
			vlan_action = true;
			break;
		case FLOW_ACTION_CSUM:
			break;
		case FLOW_ACTION_PPPOE_PUSH:
			if (half->pppoe_push)
				return -EOPNOTSUPP;
			half->pppoe_push = true;
			half->pppoe_session = act->pppoe.sid;
			break;
		default:
			hnat->unsupported_action = act->id;
			dev_warn_ratelimited(hnat->dev,
					     "HNAT rejects flow action %u\n", act->id);
			return -EOPNOTSUPP;
		}
	}
	memcpy(half->output_dst, eth, ETH_ALEN);
	memcpy(half->output_src, eth + ETH_ALEN, ETH_ALEN);
	if (!half->output_ifindex ||
	    !is_valid_ether_addr(half->output_dst) ||
	    !is_valid_ether_addr(half->output_src)) {
		hnat->invalid_l2++;
		dev_warn_ratelimited(hnat->dev,
				     "HNAT rejects invalid output L2 ifindex %d src %pM dst %pM\n",
				     half->output_ifindex, half->output_src,
				     half->output_dst);
		return -EINVAL;
	}
	return 0;
}

struct hnat_prefix_search {
	__be32 address;
	u32 network;
	u8 prefix;
	bool exact;
	bool found;
};

static void hnat_ipv4_prefix_dev(struct net_device *dev,
				 struct hnat_prefix_search *search)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	u32 address_host = ntohl(search->address);

	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		return;
	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		u32 candidate, mask;

		if (search->exact && ifa->ifa_local != search->address)
			continue;
		mask = hnat_prefix_mask(ifa->ifa_prefixlen);
		candidate = ntohl(ifa->ifa_local) & mask;
		if (!search->exact && (address_host & mask) != candidate)
			continue;
		/* A base or upper device may have several addresses.  Use the
		 * longest prefix containing the private source.
		 */
		if (search->found && ifa->ifa_prefixlen <= search->prefix)
			continue;
		search->network = candidate;
		search->prefix = ifa->ifa_prefixlen;
		search->found = true;
	}
}

static int hnat_ipv4_prefix_upper(struct net_device *dev,
				  struct netdev_nested_priv *priv)
{
	hnat_ipv4_prefix_dev(dev, priv->data);
	return 0;
}

static int hnat_ipv4_prefix(int ifindex, __be32 address, bool exact,
			    u32 *network, u8 *prefix)
{
	struct hnat_prefix_search search = {
		.address = address,
		.exact = exact,
	};
	struct netdev_nested_priv priv = { .data = &search };
	struct net_device *dev;

	rcu_read_lock();
	if (ifindex) {
		dev = dev_get_by_index_rcu(&init_net, ifindex);
		if (dev) {
			hnat_ipv4_prefix_dev(dev, &search);
			netdev_walk_all_upper_dev_rcu(dev,
						       hnat_ipv4_prefix_upper,
						       &priv);
		}
	} else {
		for_each_netdev_rcu(&init_net, dev)
			hnat_ipv4_prefix_dev(dev, &search);
	}
	rcu_read_unlock();
	if (!search.found)
		return -ENOENT;
	*network = search.network;
	*prefix = search.prefix;
	return 0;
}

static int hnat_make_spec(struct hnat_half *a, struct hnat_half *b,
			  struct hnat_flow_spec *spec)
{
	struct hnat_half *priv, *reply;
	u32 unused;
	int ret;

	if (!hnat_tuple_reverse(&a->xlate, &b->match) ||
	    !hnat_tuple_reverse(&b->xlate, &a->match))
		return -EINVAL;
	/* PPPoE push unambiguously identifies the LAN-to-WAN half.  This is
	 * important for a DNAT flow which may carry source mangles on both halves.
	 */
	if (a->pppoe_push != b->pppoe_push) {
		priv = a->pppoe_push ? a : b;
		reply = a->pppoe_push ? b : a;
	} else if (a->pppoe_push) {
		return -EOPNOTSUPP;
	} else if (a->match.src != a->xlate.src ||
		   a->match.sport != a->xlate.sport) {
		priv = a;
		reply = b;
	} else if (b->match.src != b->xlate.src ||
		   b->match.sport != b->xlate.sport) {
		priv = b;
		reply = a;
	} else {
		return -EOPNOTSUPP;
	}

	spec->cookie[0] = a->cookie;
	spec->cookie[1] = b->cookie;
	spec->private = priv->match;
	spec->public_ip = priv->xlate.src;
	spec->public_port = priv->xlate.sport;
	spec->lan_vlan = priv->input_vlan;
	spec->wan_vlan = priv->output_vlan;
	memcpy(spec->gateway_mac, priv->output_dst, ETH_ALEN);
	memcpy(spec->wan_router_mac, priv->output_src, ETH_ALEN);
	memcpy(spec->client_mac, reply->output_dst, ETH_ALEN);
	memcpy(spec->lan_router_mac, reply->output_src, ETH_ALEN);
	/* Every supported NAT must map the private half's source to public. */
	if (priv->match.src == priv->xlate.src &&
	    priv->match.sport == priv->xlate.sport)
		return -EOPNOTSUPP;
	if (priv->match.dst != priv->xlate.dst ||
	    priv->match.dport != priv->xlate.dport)
		return -EOPNOTSUPP;
	spec->pppoe = priv->pppoe_push;
	spec->pppoe_session = priv->pppoe_session;
	ret = hnat_ipv4_prefix(priv->ingress_ifindex, spec->private.src, false,
			       &spec->lan_network, &spec->lan_prefix);
	if (ret)
		return ret;
	ret = hnat_ipv4_prefix(0, spec->public_ip, true, &unused,
			       &spec->wan_prefix);
	if (ret)
		spec->wan_prefix = 24;
	return 0;
}

static int hnat_find_flow_cookie(struct sf19a2890_hnat *hnat,
				 unsigned long cookie)
{
	int i;

	for (i = 0; i < HNAT_MAX_FLOWS; i++)
		if (hnat->flows[i] &&
		    (hnat->flows[i]->cookie[0] == cookie ||
		     hnat->flows[i]->cookie[1] == cookie))
			return i;
	return -ENOENT;
}

static void hnat_flow_put_resources(struct sf19a2890_hnat *hnat,
				    struct hnat_flow *flow, u16 freed[2],
				    u8 *freed_count)
{
	if (flow->dip[0] != HNAT_NO_DIP) {
		hnat_dip_put(hnat, flow->dip[0], freed, freed_count);
		flow->dip[0] = HNAT_NO_DIP;
	}
	if (flow->dip[1] != HNAT_NO_DIP) {
		hnat_dip_put(hnat, flow->dip[1], freed, freed_count);
		flow->dip[1] = HNAT_NO_DIP;
	}
	hnat_pppoe_put(hnat, flow->pppoe);
	flow->pppoe = HNAT_NO_RESOURCE;
	if (flow->public != HNAT_NO_RESOURCE) {
		hnat_public_put(hnat, flow->public);
		flow->public = HNAT_NO_RESOURCE;
	}
	if (flow->lan != HNAT_NO_RESOURCE) {
		hnat_lan_put(hnat, flow->lan);
		flow->lan = HNAT_NO_RESOURCE;
	}
}

static int hnat_flow_get_resources(struct sf19a2890_hnat *hnat,
				   const struct hnat_flow_spec *spec,
				   struct hnat_flow *flow,
				   struct hnat_transaction *txn)
{
	int ret;

	flow->cookie[0] = spec->cookie[0];
	flow->cookie[1] = spec->cookie[1];
	flow->private = spec->private;
	flow->public_port = spec->public_port;
	flow->lastused = jiffies;
	flow->dip[0] = HNAT_NO_DIP;
	flow->dip[1] = HNAT_NO_DIP;
	flow->lan = HNAT_NO_RESOURCE;
	flow->public = HNAT_NO_RESOURCE;
	flow->pppoe = HNAT_NO_RESOURCE;
	flow->hash[HNAT_HASH_INAT] = HNAT_NO_RESOURCE;
	flow->hash[HNAT_HASH_ENAT] = HNAT_NO_RESOURCE;

	ret = hnat_lan_get(hnat, spec->lan_network, spec->lan_prefix, txn);
	if (ret < 0)
		goto err;
	flow->lan = ret;
	ret = hnat_public_get(hnat, spec->public_ip, spec->wan_prefix,
			      spec->wan_vlan, txn);
	if (ret < 0)
		goto err;
	flow->public = ret;
	if (spec->pppoe) {
		ret = hnat_pppoe_get(hnat, spec->pppoe_session, txn);
		if (ret < 0)
			goto err;
		flow->pppoe = ret;
	}
	ret = hnat_dip_get(hnat, spec->private.src, spec->lan_vlan,
			   spec->client_mac, spec->lan_router_mac, txn);
	if (ret < 0)
		goto err;
	flow->dip[0] = ret;
	ret = hnat_dip_get(hnat, spec->private.dst, spec->wan_vlan,
			   spec->gateway_mac, spec->wan_router_mac, txn);
	if (ret < 0)
		goto err;
	flow->dip[1] = ret;
	ret = hnat_napt_hash_reserve(hnat, flow, HNAT_HASH_INAT);
	if (ret)
		goto err;
	ret = hnat_napt_hash_reserve(hnat, flow, HNAT_HASH_ENAT);
	if (ret)
		goto err;
	return 0;

err:
	hnat_napt_hash_release(hnat, flow, HNAT_HASH_ENAT);
	hnat_napt_hash_release(hnat, flow, HNAT_HASH_INAT);
	hnat_flow_put_resources(hnat, flow, NULL, NULL);
	return ret;
}

static int hnat_program_flow(struct sf19a2890_hnat *hnat,
			     struct hnat_flow *flow, u16 index,
			     struct hnat_transaction *txn)
{
	struct hnat_word word;
	u16 key[3];
	int dir, ret;

	ret = hnat_program_created(hnat, txn);
	if (ret)
		return ret;
	hnat_napt_word(hnat, flow, &word);
	ret = hnat_table_write(hnat, HNAT_NAPT, index, &word);
	if (ret)
		return ret;
	for (dir = 0; dir < HNAT_HASH_DIR_COUNT; dir++) {
		hnat_napt_keys(hnat, flow, dir == HNAT_HASH_INAT, key);
		ret = hnat_write_napt_hash_bucket(
			hnat, dir, hnat_hash_level(flow->hash[dir]),
			key[hnat_hash_level(flow->hash[dir])], flow, index);
		if (ret)
			return ret;
	}
	hnat_napt_valid_word(hnat, index / 32, flow, index, &word);
	return hnat_table_write(hnat, HNAT_NAPT_VALID, index / 32, &word);
}

static int hnat_install_flow(struct sf19a2890_hnat *hnat,
			     const struct hnat_flow_spec *spec)
{
	struct hnat_transaction txn = {};
	struct hnat_flow *flow;
	u16 lan_vlan, wan_vlan;
	int index, ret;

	if (hnat->degraded)
		return -EIO;
	for (index = 0; index < HNAT_MAX_FLOWS; index++)
		if (!hnat->flows[index])
			break;
	if (index == HNAT_MAX_FLOWS)
		return -ENOSPC;
	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (!flow)
		return -ENOMEM;
	ret = hnat_flow_get_resources(hnat, spec, flow, &txn);
	if (ret)
		goto free_flow;
	ret = hnat_program_flow(hnat, flow, index, &txn);
	if (ret) {
		hnat_napt_hash_release(hnat, flow, HNAT_HASH_ENAT);
		hnat_napt_hash_release(hnat, flow, HNAT_HASH_INAT);
		hnat_flow_put_resources(hnat, flow, NULL, NULL);
		hnat_degrade(hnat, ret);
		goto free_flow;
	}
	hnat->flows[index] = flow;
	hnat->active_count++;
	lan_vlan = hnat->dip[flow->dip[0]].vlan;
	wan_vlan = hnat->dip[flow->dip[1]].vlan;
	dev_dbg(hnat->dev,
		"HNAT flow %d: %pI4:%u -> %pI4:%u NAT %pI4:%u VLAN %u->%u PPPoE %u/%u\n",
		index, &flow->private.src, ntohs(flow->private.sport),
		&flow->private.dst, ntohs(flow->private.dport),
		&hnat->public[flow->public].ip, ntohs(flow->public_port),
		lan_vlan == HNAT_NO_VLAN ? 0 : hnat->vlan[lan_vlan].vid,
		wan_vlan == HNAT_NO_VLAN ? 0 : hnat->vlan[wan_vlan].vid,
		flow->pppoe != HNAT_NO_RESOURCE,
		flow->pppoe == HNAT_NO_RESOURCE ? 0 :
			hnat->pppoe[flow->pppoe].session);
	return 0;

free_flow:
	kfree(flow);
	return ret;
}

static int hnat_replace(struct sf19a2890_hnat *hnat,
			struct flow_cls_offload *cls)
{
	struct hnat_flow_spec spec = {};
	struct hnat_pending *pending, *match = NULL;
	struct hnat_half half = {};
	int ret;

	if (hnat_find_flow_cookie(hnat, cls->cookie) >= 0)
		return -EEXIST;
	if (hnat->degraded)
		return -EIO;
	ret = hnat_parse_half(hnat, cls, &half);
	if (ret) {
		hnat->parse_errors++;
		dev_warn_ratelimited(hnat->dev,
				     "HNAT rejects half cookie %lx ret %d ingress %d output %d tuple %pI4:%u -> %pI4:%u\n",
				     cls->cookie, ret, half.ingress_ifindex,
				     half.output_ifindex, &half.match.src,
				     ntohs(half.match.sport), &half.match.dst,
				     ntohs(half.match.dport));
		return ret;
	}
	/* Flowtable supplies one flower rule for each direction, but the HNAT
	 * entry is bidirectional.  Hold the first half until its translated
	 * reverse arrives; -EAGAIN keeps flowtable from treating it as offloaded.
	 */
	list_for_each_entry(pending, &hnat->pending, list) {
		if (pending->half.cookie == half.cookie)
			return -EAGAIN;
		if (hnat_tuple_reverse(&half.xlate, &pending->half.match) &&
		    hnat_tuple_reverse(&pending->half.xlate, &half.match)) {
			match = pending;
			break;
		}
	}
	if (!match) {
		if (hnat->pending_count == HNAT_MAX_PENDING)
			return -ENOSPC;
		pending = kmalloc(sizeof(*pending), GFP_KERNEL);
		if (!pending)
			return -ENOMEM;
		pending->half = half;
		list_add_tail(&pending->list, &hnat->pending);
		hnat->pending_count++;
		return -EAGAIN;
	}
	ret = hnat_make_spec(&match->half, &half, &spec);
	if (ret) {
		dev_warn_ratelimited(hnat->dev,
				     "HNAT cannot pair cookies %lx/%lx: %d\n",
				     match->half.cookie, half.cookie, ret);
	} else {
		ret = hnat_install_flow(hnat, &spec);
	}
	list_del(&match->list);
	kfree(match);
	hnat->pending_count--;
	return ret;
}

static void hnat_remove_flow(struct sf19a2890_hnat *hnat, u16 index)
{
	struct hnat_flow *flow = hnat->flows[index];
	struct hnat_word word;
	u16 napt_key[HNAT_HASH_DIR_COUNT];
	u16 dip_key[2];
	u16 freed[2];
	u8 napt_level[HNAT_HASH_DIR_COUNT];
	u8 freed_count = 0;
	int dir, i, ret = 0;

	for (dir = 0; dir < HNAT_HASH_DIR_COUNT; dir++) {
		u16 keys[3];

		napt_level[dir] = hnat_hash_level(flow->hash[dir]);
		hnat_napt_keys(hnat, flow, dir == HNAT_HASH_INAT, keys);
		napt_key[dir] = keys[napt_level[dir]];
	}
	hnat->flows[index] = NULL;
	hnat->active_count--;
	hnat_napt_hash_release(hnat, flow, HNAT_HASH_ENAT);
	hnat_napt_hash_release(hnat, flow, HNAT_HASH_INAT);
	hnat_flow_put_resources(hnat, flow, freed, &freed_count);

	if (!hnat->degraded) {
		hnat_napt_valid_word(hnat, index / 32, NULL, 0, &word);
		ret = hnat_table_write(hnat, HNAT_NAPT_VALID, index / 32,
				       &word);
		for (dir = 0; !ret && dir < HNAT_HASH_DIR_COUNT; dir++)
			ret = hnat_write_napt_hash_bucket(hnat, dir,
					napt_level[dir], napt_key[dir], NULL, 0);
		for (i = 0; !ret && i < freed_count; i++) {
			hnat_dip_valid_word(hnat, freed[i] / 32, &word);
			ret = hnat_table_write(hnat, HNAT_DIP_VALID,
					       freed[i] / 32, &word);
		}
		for (i = 0; !ret && i < freed_count; i++) {
			u8 level = hnat_hash_level(hnat->dip[freed[i]].hash);
			u16 keys[2];

			hnat_dip_keys(&hnat->dip[freed[i]], keys);
			dip_key[i] = keys[level];
			ret = hnat_write_dip_hash_bucket(hnat, level, dip_key[i]);
		}
		if (!ret)
			hnat_write_lan_csrs(hnat);
		else
			hnat_degrade(hnat, ret);
	}
	dev_dbg(hnat->dev, "removed HNAT flow %u\n", index);
	kfree(flow);
}

static int hnat_destroy(struct sf19a2890_hnat *hnat,
			struct flow_cls_offload *cls)
{
	struct hnat_pending *pending, *tmp;
	int i;

	list_for_each_entry_safe(pending, tmp, &hnat->pending, list) {
		if (pending->half.cookie == cls->cookie) {
			list_del(&pending->list);
			kfree(pending);
			hnat->pending_count--;
			return 0;
		}
	}
	i = hnat_find_flow_cookie(hnat, cls->cookie);
	if (i < 0)
		return i;
	hnat_remove_flow(hnat, i);
	return 0;
}

static void hnat_destroy_worker(struct work_struct *work)
{
	struct hnat_destroy_work *destroy = container_of(
		work, struct hnat_destroy_work, work);
	struct flow_cls_offload cls = {
		.cookie = destroy->cookie,
	};

	mutex_lock(&destroy->hnat->lock);
	hnat_destroy(destroy->hnat, &cls);
	mutex_unlock(&destroy->hnat->lock);
	kfree(destroy);
}

static int hnat_defer_destroy(struct sf19a2890_hnat *hnat,
			      unsigned long cookie)
{
	struct hnat_destroy_work *destroy;

	destroy = kmalloc(sizeof(*destroy), GFP_KERNEL);
	if (!destroy)
		return -ENOMEM;
	destroy->hnat = hnat;
	destroy->cookie = cookie;
	INIT_WORK(&destroy->work, hnat_destroy_worker);
	queue_work(hnat->destroy_wq, &destroy->work);
	return 0;
}

static int hnat_stats(struct sf19a2890_hnat *hnat,
		      struct flow_cls_offload *cls)
{
	int flow;

	flow = hnat_find_flow_cookie(hnat, cls->cookie);
	if (flow < 0)
		return flow;

	/* Table 24 counters are read-clear and indexed by shared DMAC entries,
	 * not by NAPT entries.  They cannot attribute activity to one flow.
	 * Returning the install time lets flowtable expire the hardware entry;
	 * the next software-path packet can then create it again.
	 */
	cls->stats.lastused = hnat->flows[flow]->lastused;
	return 0;
}

static int hnat_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct sf19a2890_hnat *hnat = cb_priv;
	struct flow_cls_offload *cls = type_data;
	int ret;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;
	/* Netfilter submits add, delete and stats work on unbound workqueues.
	 * Do not block their workers behind this device's table lock: a burst of
	 * flows would otherwise make workqueue concurrency grow without bound.
	 * Failed add/stats callbacks naturally stay on (or return to) software.
	 * Deletes cannot be dropped, so serialize contended ones on our queue.
	 */
	if (!mutex_trylock(&hnat->lock)) {
		if (cls->command == FLOW_CLS_DESTROY)
			return hnat_defer_destroy(hnat, cls->cookie);
		return -EBUSY;
	}
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		ret = hnat_replace(hnat, cls);
		break;
	case FLOW_CLS_DESTROY:
		ret = hnat_destroy(hnat, cls);
		break;
	case FLOW_CLS_STATS:
		ret = hnat_stats(hnat, cls);
		break;
	default:
		ret = -EOPNOTSUPP;
	}
	mutex_unlock(&hnat->lock);
	return ret;
}

static int hnat_indr_block_cb(enum tc_setup_type type, void *type_data,
			      void *cb_priv)
{
	struct hnat_indr_binding *binding = cb_priv;

	return hnat_block_cb(type, type_data, binding->hnat);
}

static void hnat_indr_release(void *cb_priv)
{
	struct hnat_indr_binding *binding = cb_priv;

	list_del(&binding->list);
	kfree(binding);
}

static int hnat_lower_walk(struct net_device *lower,
			   struct netdev_nested_priv *priv)
{
	if (lower == priv->data) {
		priv->flags = 1;
		return 1;
	}
	return 0;
}

static bool hnat_uses_mac(struct sf19a2890_hnat *hnat,
			  struct net_device *netdev)
{
	struct netdev_nested_priv priv = { .data = hnat->ndev };

	if (netdev == hnat->ndev)
		return true;
	netdev_walk_all_lower_dev(netdev, hnat_lower_walk, &priv);
	return priv.flags;
}

static struct hnat_indr_binding *
hnat_indr_find(struct sf19a2890_hnat *hnat, struct net_device *netdev)
{
	struct hnat_indr_binding *binding;

	list_for_each_entry(binding, &hnat->indr_bindings, list)
		if (binding->netdev == netdev)
			return binding;
	return NULL;
}

static int hnat_indr_setup(struct net_device *netdev, struct Qdisc *sch,
			   void *cb_priv, enum tc_setup_type type,
			   void *type_data, void *data,
			   void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct sf19a2890_hnat *hnat = cb_priv;
	struct flow_block_offload *f = type_data;
	struct hnat_indr_binding *binding;
	struct flow_block_cb *block_cb;

	if ((type != TC_SETUP_BLOCK && type != TC_SETUP_FT) || !netdev ||
	    !hnat_uses_mac(hnat, netdev))
		return -EOPNOTSUPP;
	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		if (hnat_indr_find(hnat, netdev))
			return -EEXIST;
		binding = kzalloc(sizeof(*binding), GFP_KERNEL);
		if (!binding)
			return -ENOMEM;
		binding->hnat = hnat;
		binding->netdev = netdev;
		list_add(&binding->list, &hnat->indr_bindings);
		block_cb = flow_indr_block_cb_alloc(hnat_indr_block_cb, binding,
						    binding, hnat_indr_release, f,
						netdev, sch, data, hnat, cleanup);
		if (IS_ERR(block_cb)) {
			list_del(&binding->list);
			kfree(binding);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		return 0;
	case FLOW_BLOCK_UNBIND:
		binding = hnat_indr_find(hnat, netdev);
		if (!binding)
			return -ENOENT;
		block_cb = flow_block_cb_lookup(f->block, hnat_indr_block_cb,
						binding);
		if (!block_cb)
			return -ENOENT;
		flow_indr_block_cb_remove(block_cb, f);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int hnat_setup_block(struct sf19a2890_hnat *hnat,
			    struct flow_block_offload *f)
{
	struct flow_block_cb *block_cb;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	f->driver_block_list = &hnat->block_cb_list;
	switch (f->command) {
	case FLOW_BLOCK_BIND:
		block_cb = flow_block_cb_lookup(f->block, hnat_block_cb, hnat);
		if (block_cb) {
			flow_block_cb_incref(block_cb);
			return 0;
		}
		block_cb = flow_block_cb_alloc(hnat_block_cb, hnat, hnat, NULL);
		if (IS_ERR(block_cb))
			return PTR_ERR(block_cb);
		flow_block_cb_incref(block_cb);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &hnat->block_cb_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, hnat_block_cb, hnat);
		if (!block_cb)
			return -ENOENT;
		if (!flow_block_cb_decref(block_cb)) {
			flow_block_cb_remove(block_cb, f);
			list_del(&block_cb->driver_list);
		}
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

int sf19a2890_hnat_setup_tc(struct sf19a2890_hnat *hnat,
			    struct net_device *ndev,
			    enum tc_setup_type type, void *type_data)
{
	if (!hnat || ndev != hnat->ndev)
		return -EOPNOTSUPP;
	switch (type) {
	case TC_SETUP_BLOCK:
	case TC_SETUP_FT:
		return hnat_setup_block(hnat, type_data);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL_GPL(sf19a2890_hnat_setup_tc);

int sf19a2890_hnat_restore(struct sf19a2890_hnat *hnat)
{
	int ret;

	if (!hnat)
		return 0;
	mutex_lock(&hnat->lock);
	/* DWMAC reset also clears HNAT, so reconstruct live entries from the
	 * compact flow/resource metadata before traffic resumes.
	 */
	ret = hnat_replay(hnat);
	if (ret)
		hnat_degrade(hnat, ret);
	else {
		hnat->degraded = false;
		hnat->reset_count++;
	}
	mutex_unlock(&hnat->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sf19a2890_hnat_restore);

struct hnat_ref_check {
	u16 lan[HNAT_LAN_COUNT];
	u16 vlan[HNAT_VLAN_COUNT];
	u16 public[HNAT_PUBLIC_COUNT];
	u16 dip[HNAT_DIP_COUNT];
	u16 dmac[HNAT_DMAC_COUNT];
	u16 rmac[HNAT_RMAC_COUNT];
	u16 pppoe[HNAT_PPPOE_COUNT];
};

static bool hnat_napt_hash_consistent(struct sf19a2890_hnat *hnat,
				      const struct hnat_flow *flow,
				      enum hnat_hash_dir dir)
{
	static const u8 slots[] = { 2, 4, 2 };
	u8 level = hnat_hash_level(flow->hash[dir]);
	u8 slot = hnat_hash_slot(flow->hash[dir]);
	u16 key[3];

	if (level >= ARRAY_SIZE(slots) || slot >= slots[level])
		return false;
	hnat_napt_keys(hnat, flow, dir == HNAT_HASH_INAT, key);
	return test_bit(hnat_napt_hash_bit(level, key[level], slot),
			hnat->napt_hash_used[dir]);
}

static bool hnat_dip_hash_consistent(struct sf19a2890_hnat *hnat,
				     const struct hnat_dip_resource *dip)
{
	u8 level = hnat_hash_level(dip->hash);
	u8 slot = hnat_hash_slot(dip->hash);
	u16 key[2];

	if (level > 1 || slot > 3 || (!level && slot == 2))
		return false;
	hnat_dip_keys(dip, key);
	return test_bit(hnat_dip_hash_bit(level, key[level], slot),
			hnat->dip_hash_used);
}

static unsigned int hnat_metadata_check(struct sf19a2890_hnat *hnat,
					struct hnat_ref_check *expected,
					unsigned int used[7])
{
	struct hnat_pending *pending;
	unsigned int errors = 0, flows = 0, pending_count = 0;
	int i, dir;

	for (i = 0; i < HNAT_MAX_FLOWS; i++) {
		struct hnat_flow *flow = hnat->flows[i];

		if (!flow)
			continue;
		flows++;
		if (flow->lan >= HNAT_LAN_COUNT ||
		    !hnat->lan[flow->lan].refs)
			errors++;
		else
			expected->lan[flow->lan]++;
		if (flow->public >= HNAT_PUBLIC_COUNT ||
		    !hnat->public[flow->public].refs)
			errors++;
		else
			expected->public[flow->public]++;
		for (dir = 0; dir < 2; dir++) {
			if (flow->dip[dir] >= HNAT_DIP_COUNT ||
			    !hnat->dip[flow->dip[dir]].refs)
				errors++;
			else
				expected->dip[flow->dip[dir]]++;
		}
		if (flow->pppoe != HNAT_NO_RESOURCE) {
			if (flow->pppoe >= HNAT_PPPOE_COUNT ||
			    !hnat->pppoe[flow->pppoe].refs)
				errors++;
			else
				expected->pppoe[flow->pppoe]++;
		}
		for (dir = 0; dir < HNAT_HASH_DIR_COUNT; dir++)
			if (!hnat_napt_hash_consistent(hnat, flow, dir))
				errors++;
	}
	if (flows != hnat->active_count)
		errors++;
	list_for_each_entry(pending, &hnat->pending, list)
		pending_count++;
	if (pending_count != hnat->pending_count)
		errors++;

	for (i = 0; i < HNAT_PUBLIC_COUNT; i++) {
		struct hnat_public_resource *res = &hnat->public[i];

		if (res->refs) {
			used[2]++;
			if (res->vlan != HNAT_NO_VLAN) {
				if (res->vlan >= HNAT_NO_VLAN)
					errors++;
				else
					expected->vlan[res->vlan]++;
			}
		}
		if (res->refs != expected->public[i])
			errors++;
	}
	for (i = 0; i < HNAT_DIP_COUNT; i++) {
		struct hnat_dip_resource *res = &hnat->dip[i];

		if (res->refs) {
			used[3]++;
			if (res->vlan != HNAT_NO_VLAN) {
				if (res->vlan >= HNAT_NO_VLAN)
					errors++;
				else
					expected->vlan[res->vlan]++;
			}
			if (res->dmac >= HNAT_DMAC_COUNT)
				errors++;
			else
				expected->dmac[res->dmac]++;
			if (!hnat_dip_hash_consistent(hnat, res))
				errors++;
		}
		if (res->refs != expected->dip[i])
			errors++;
	}
	for (i = 0; i < HNAT_DMAC_COUNT; i++) {
		struct hnat_dmac_resource *res = &hnat->dmac[i];

		if (res->refs) {
			used[4]++;
			if (res->rmac >= HNAT_RMAC_COUNT)
				errors++;
			else
				expected->rmac[res->rmac]++;
		}
		if (res->refs != expected->dmac[i])
			errors++;
	}
	for (i = 0; i < HNAT_LAN_COUNT; i++) {
		if (hnat->lan[i].refs)
			used[0]++;
		if (hnat->lan[i].refs != expected->lan[i])
			errors++;
	}
	for (i = 0; i < HNAT_NO_VLAN; i++) {
		if (hnat->vlan[i].refs)
			used[1]++;
		if (hnat->vlan[i].refs != expected->vlan[i])
			errors++;
	}
	for (i = 0; i < HNAT_RMAC_COUNT; i++) {
		if (hnat->rmac[i].refs)
			used[5]++;
		if (hnat->rmac[i].refs != expected->rmac[i])
			errors++;
	}
	for (i = 0; i < HNAT_PPPOE_COUNT; i++) {
		if (hnat->pppoe[i].refs)
			used[6]++;
		if (hnat->pppoe[i].refs != expected->pppoe[i])
			errors++;
	}
	if (bitmap_weight(hnat->napt_hash_used[HNAT_HASH_INAT],
			  HNAT_NAPT_HASH_SLOTS) != flows ||
	    bitmap_weight(hnat->napt_hash_used[HNAT_HASH_ENAT],
			  HNAT_NAPT_HASH_SLOTS) != flows ||
	    bitmap_weight(hnat->dip_hash_used, HNAT_DIP_HASH_SLOTS) != used[3])
		errors++;
	return errors;
}

static int hnat_debug_show(struct seq_file *s, void *unused)
{
	struct sf19a2890_hnat *hnat = s->private;
	struct hnat_ref_check *expected;
	unsigned int used[7] = {};
	unsigned int errors;
	size_t metadata_bytes;

	expected = kzalloc(sizeof(*expected), GFP_KERNEL);
	if (!expected)
		return -ENOMEM;
	mutex_lock(&hnat->lock);
	errors = hnat_metadata_check(hnat, expected, used);
	metadata_bytes = sizeof(*hnat) +
		HNAT_MAX_FLOWS * sizeof(*hnat->flows) +
		HNAT_DIP_COUNT * sizeof(*hnat->dip) +
		hnat->active_count * sizeof(struct hnat_flow) +
		hnat->pending_count * sizeof(struct hnat_pending);
	seq_printf(s, "state: %s\nactive_flows: %u/%u\npending_halves: %u/%u\nmetadata_bytes: %zu\nmetadata_errors: %u\nresets: %u\ntable_errors: %u\nparse_errors: %u\nunsupported_action: %u\ninvalid_l2: %u\n",
		   hnat->degraded ? "degraded" : "active",
		   hnat->active_count, HNAT_MAX_FLOWS,
		   hnat->pending_count, HNAT_MAX_PENDING, metadata_bytes, errors,
		   hnat->reset_count,
		   hnat->table_errors, hnat->parse_errors,
		   hnat->unsupported_action, hnat->invalid_l2);
	seq_printf(s, "resources: lan %u/%u vlan %u/%u public %u/%u dip %u/%u dmac %u/%u rmac %u/%u pppoe %u/%u\n",
		   used[0], HNAT_LAN_COUNT, used[1], HNAT_NO_VLAN,
		   used[2], HNAT_PUBLIC_COUNT, used[3], HNAT_DIP_COUNT,
		   used[4], HNAT_DMAC_COUNT, used[5], HNAT_RMAC_COUNT,
		   used[6], HNAT_PPPOE_COUNT);
	seq_printf(s, "hash_inat: %u/%u %u/%u %u/%u\nhash_enat: %u/%u %u/%u %u/%u\nhash_dip: %u/%u %u/%u\n",
		   bitmap_weight(hnat->napt_hash_used[HNAT_HASH_INAT],
				 HNAT_NAPT_HASH1_SLOTS), HNAT_NAPT_HASH1_SLOTS,
		   bitmap_weight(hnat->napt_hash_used[HNAT_HASH_INAT] +
				 BIT_WORD(HNAT_NAPT_HASH1_SLOTS),
				 HNAT_NAPT_HASH2_SLOTS), HNAT_NAPT_HASH2_SLOTS,
		   bitmap_weight(hnat->napt_hash_used[HNAT_HASH_INAT] +
				 BIT_WORD(HNAT_NAPT_HASH1_SLOTS +
					  HNAT_NAPT_HASH2_SLOTS),
				 HNAT_NAPT_HASH3_SLOTS), HNAT_NAPT_HASH3_SLOTS,
		   bitmap_weight(hnat->napt_hash_used[HNAT_HASH_ENAT],
				 HNAT_NAPT_HASH1_SLOTS), HNAT_NAPT_HASH1_SLOTS,
		   bitmap_weight(hnat->napt_hash_used[HNAT_HASH_ENAT] +
				 BIT_WORD(HNAT_NAPT_HASH1_SLOTS),
				 HNAT_NAPT_HASH2_SLOTS), HNAT_NAPT_HASH2_SLOTS,
		   bitmap_weight(hnat->napt_hash_used[HNAT_HASH_ENAT] +
				 BIT_WORD(HNAT_NAPT_HASH1_SLOTS +
					  HNAT_NAPT_HASH2_SLOTS),
				 HNAT_NAPT_HASH3_SLOTS), HNAT_NAPT_HASH3_SLOTS,
		   bitmap_weight(hnat->dip_hash_used, HNAT_DIP_HASH1_SLOTS),
		   HNAT_DIP_HASH1_SLOTS,
		   bitmap_weight(hnat->dip_hash_used +
				 BIT_WORD(HNAT_DIP_HASH1_SLOTS),
				 HNAT_DIP_HASH2_SLOTS), HNAT_DIP_HASH2_SLOTS);
	seq_printf(s, "csr1: 0x%08x\ntable_config: 0x%08x\n",
		   readl(hnat->ioaddr + HNAT_CSR(1)),
		   readl(hnat->ioaddr + HNAT_TB_CONFIG));
	seq_printf(s, "rx_enter: %u\nno_hit: %u\ntx_enat: %u\nrx_enat: %u\nrx_inat: %u\n",
		   readl(hnat->ioaddr + HNAT_CSR_BASE + 0x100),
		   readl(hnat->ioaddr + HNAT_CSR_BASE + 0x144),
		   readl(hnat->ioaddr + HNAT_CSR_BASE + 0x16c),
		   readl(hnat->ioaddr + HNAT_CSR_BASE + 0x170),
		   readl(hnat->ioaddr + HNAT_CSR_BASE + 0x174));
	mutex_unlock(&hnat->lock);
	kfree(expected);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(hnat_debug);

static void hnat_destroy_workqueue(void *data)
{
	struct sf19a2890_hnat *hnat = data;

	destroy_workqueue(hnat->destroy_wq);
}

struct sf19a2890_hnat *
sf19a2890_hnat_create(struct device *dev, void __iomem *ioaddr)
{
	struct sf19a2890_hnat *hnat;

	hnat = devm_kzalloc(dev, sizeof(*hnat), GFP_KERNEL);
	if (!hnat)
		return ERR_PTR(-ENOMEM);
	hnat->flows = devm_kcalloc(dev, HNAT_MAX_FLOWS,
				    sizeof(*hnat->flows), GFP_KERNEL);
	hnat->dip = devm_kcalloc(dev, HNAT_DIP_COUNT,
				  sizeof(*hnat->dip), GFP_KERNEL);
	if (!hnat->flows || !hnat->dip)
		return ERR_PTR(-ENOMEM);
	hnat->destroy_wq = alloc_ordered_workqueue("sf19a2890-hnat-destroy",
						    WQ_MEM_RECLAIM);
	if (!hnat->destroy_wq)
		return ERR_PTR(-ENOMEM);
	if (devm_add_action_or_reset(dev, hnat_destroy_workqueue, hnat))
		return ERR_PTR(-ENOMEM);
	hnat->dev = dev;
	hnat->ioaddr = ioaddr;
	mutex_init(&hnat->lock);
	INIT_LIST_HEAD(&hnat->pending);
	INIT_LIST_HEAD(&hnat->block_cb_list);
	INIT_LIST_HEAD(&hnat->indr_bindings);
	return hnat;
}
EXPORT_SYMBOL_GPL(sf19a2890_hnat_create);

static int hnat_start_empty(struct sf19a2890_hnat *hnat)
{
	struct hnat_word word = {};
	int i, ret;

	/* Only validity tables need clearing.  Payload and hash words are
	 * unreachable until their corresponding validity bit is set.
	 */
	writel(HNAT_CSR1_VALUE, hnat->ioaddr + HNAT_CSR(1));
	hnat_write_config_csrs(hnat);
	hnat_write_lan_csrs(hnat);
	for (i = 0; i < HNAT_MAX_FLOWS / 32; i++) {
		ret = hnat_table_write(hnat, HNAT_NAPT_VALID, i, &word);
		if (ret)
			return ret;
	}
	for (i = 0; i < HNAT_DIP_COUNT / 32; i++) {
		ret = hnat_table_write(hnat, HNAT_DIP_VALID, i, &word);
		if (ret)
			return ret;
	}
	return 0;
}

int sf19a2890_hnat_start(struct sf19a2890_hnat *hnat, struct net_device *ndev)
{
	int ret;

	hnat->ndev = ndev;
	ret = hnat_start_empty(hnat);
	if (ret) {
		hnat_degrade(hnat, ret);
		return ret;
	}
	hnat->degraded = false;
	ret = flow_indr_dev_register(hnat_indr_setup, hnat);
	if (ret) {
		writel(0, hnat->ioaddr + HNAT_CSR(1));
		return ret;
	}
	hnat->debugfs = debugfs_create_file("sf19a2890-hnat", 0444, NULL, hnat,
					    &hnat_debug_fops);
	dev_info(hnat->dev, "HNAT ready: 1024 IPv4 TCP/UDP flows, VLAN/PPPoE\n");
	return 0;
}
EXPORT_SYMBOL_GPL(sf19a2890_hnat_start);

void sf19a2890_hnat_stop(struct sf19a2890_hnat *hnat)
{
	struct hnat_pending *pending, *tmp;
	int i;

	if (!hnat)
		return;
	debugfs_remove(hnat->debugfs);
	flow_indr_dev_unregister(hnat_indr_setup, hnat, hnat_indr_release);
	flush_workqueue(hnat->destroy_wq);
	mutex_lock(&hnat->lock);
	writel(0, hnat->ioaddr + HNAT_CSR(1));
	list_for_each_entry_safe(pending, tmp, &hnat->pending, list) {
		list_del(&pending->list);
		kfree(pending);
	}
	for (i = 0; i < HNAT_MAX_FLOWS; i++) {
		kfree(hnat->flows[i]);
		hnat->flows[i] = NULL;
	}
	memset(hnat->lan, 0, sizeof(hnat->lan));
	memset(hnat->vlan, 0, sizeof(hnat->vlan));
	memset(hnat->public, 0, sizeof(hnat->public));
	memset(hnat->dip, 0, sizeof(*hnat->dip) * HNAT_DIP_COUNT);
	memset(hnat->dmac, 0, sizeof(hnat->dmac));
	memset(hnat->rmac, 0, sizeof(hnat->rmac));
	memset(hnat->pppoe, 0, sizeof(hnat->pppoe));
	bitmap_zero(hnat->napt_hash_used[HNAT_HASH_INAT],
		    HNAT_NAPT_HASH_SLOTS);
	bitmap_zero(hnat->napt_hash_used[HNAT_HASH_ENAT],
		    HNAT_NAPT_HASH_SLOTS);
	bitmap_zero(hnat->dip_hash_used, HNAT_DIP_HASH_SLOTS);
	hnat->active_count = 0;
	hnat->pending_count = 0;
	hnat->degraded = false;
	hnat->ndev = NULL;
	mutex_unlock(&hnat->lock);
}
EXPORT_SYMBOL_GPL(sf19a2890_hnat_stop);

MODULE_DESCRIPTION("Siflower SF19A2890 hardware NAT offload engine");
MODULE_LICENSE("GPL");
