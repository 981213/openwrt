/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SF19A2890_HNAT_H
#define __SF19A2890_HNAT_H

#include <linux/netdevice.h>

struct device;
struct sf19a2890_hnat;
struct stmmac_priv;

struct sf19a2890_hnat *
sf19a2890_hnat_create(struct device *dev, void __iomem *ioaddr);
int sf19a2890_hnat_start(struct sf19a2890_hnat *hnat,
			 struct net_device *ndev);
void sf19a2890_hnat_stop(struct sf19a2890_hnat *hnat);
int sf19a2890_hnat_setup_tc(struct sf19a2890_hnat *hnat,
			    struct net_device *ndev,
			    enum tc_setup_type type, void *type_data);
int sf19a2890_hnat_restore(struct sf19a2890_hnat *hnat);

#endif
