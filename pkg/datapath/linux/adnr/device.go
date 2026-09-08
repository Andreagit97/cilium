// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/time"
)

func getDevice(index int, devices statedb.Table[*tables.Device], db *statedb.DB, timeout time.Duration) (*tables.Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		epDev, _, watch, found := devices.GetWatch(db.ReadTxn(), tables.DeviceByIndex(index))
		if found {
			return epDev, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device %d not found: %w", index, ctx.Err())
		case <-watch:
		}
	}
}

func getRouteIndex(nodeIP net.IP) (int, error) {
	// Search routes for the node
	routes, err := netlink.RouteGet(nodeIP)
	if err != nil {
		return 0, fmt.Errorf("unable to lookup route for node %s: %w", nodeIP.String(), err)
	}

	if len(routes) == 0 {
		return 0, fmt.Errorf("no route found to destination %s", nodeIP.String())
	}

	firstRoute := routes[0]
	if firstRoute.Gw != nil &&
		!firstRoute.Gw.IsUnspecified() &&
		!firstRoute.Gw.Equal(nodeIP) {
		return 0, fmt.Errorf(
			"%w. node %s uses gateway %s",
			errNodeNotOnSameL2,
			nodeIP,
			firstRoute.Gw,
		)
	}

	linkIndex := firstRoute.LinkIndex

	if linkIndex != 1 {
		return linkIndex, nil
	}

	// Special treatment if the route points to the loopback, lookup the
	// local route and use that ifindex
	family := netlink.FAMILY_V4
	dst := &net.IPNet{IP: nodeIP, Mask: net.CIDRMask(32, 32)}
	if nodeIP.To4() == nil {
		family = netlink.FAMILY_V6
		dst.Mask = net.CIDRMask(128, 128)
	}

	filter := &netlink.Route{
		Table: int(routeReconciler.TableLocal),
		Dst:   dst,
	}

	routes, err = safenetlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, fmt.Errorf("unable to find local route for destination %s: %w", nodeIP, err)
	}

	if len(routes) == 0 {
		return 0, fmt.Errorf("unable to find local route for destination %s which is routed over loopback", nodeIP)
	}
	return routes[0].LinkIndex, nil
}
