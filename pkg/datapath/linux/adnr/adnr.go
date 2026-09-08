package adnr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
)

var (
	errNodeNotOnSameL2 = errors.New("node is not on the same L2")
)

func getOwnerName(nodeName string) string {
	const adnrOwnerPrefix = "adnr/"
	return adnrOwnerPrefix + nodeName
}

func deleteNodeRoutes(rm *routeReconciler.DesiredRouteManager, nodeName string) error {
	owner, err := rm.GetOwner(getOwnerName(nodeName))
	if err != nil {
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}
		return fmt.Errorf("getting route owner for node %s: %w", nodeName, err)
	}
	return rm.RemoveOwner(owner)
}

func (h *Handler) getNodeRoutes(nodeName string, nodeIP net.IP, podCIDRs []netip.Prefix) ([]routeReconciler.DesiredRoute, error) {
	// We check if the remote node is reachable on the same L2 Network
	index, err := h.getRouteIndex(nodeIP)
	if err != nil {
		if errors.Is(errNodeNotOnSameL2, err) &&
			h.cfg.DirectRoutingSkipUnreachable {
			h.logger.Debug("route to destination contains gateway, skipping route as not directly reachable",
				logfields.NodeName, nodeName,
				logfields.Message, err.Error(),
			)
			return nil, nil
		}
		return nil, err
	}

	// We now get the device associated with the index we obtained from the route.
	const getDeviceTimeout = 5 * time.Second
	dev, err := getDevice(index, h.devices, h.db, getDeviceTimeout)
	if err != nil {
		return nil, fmt.Errorf("getting device for node %s: %w", nodeName, err)
	}

	owner, err := h.routeManager.GetOrRegisterOwner(getOwnerName(nodeName))
	if err != nil {
		return nil, fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}

	routes := make([]routeReconciler.DesiredRoute, 0, len(podCIDRs))
	ip, _ := netip.AddrFromSlice(nodeIP)
	for _, prefix := range podCIDRs {
		routes = append(routes, routeReconciler.DesiredRoute{
			Owner:         owner,
			Table:         routeReconciler.TableMain, // ask!: TableMain is ok?
			Prefix:        prefix,
			AdminDistance: routeReconciler.AdminDistanceDefault,
			Nexthop:       ip.Unmap(),
			Device:        dev,
		})
	}
	return routes, nil
}

func (h *Handler) updateNodeRoutes(n *node.Node) error {
	routes := []routeReconciler.DesiredRoute{}
	nodeName := n.Fullname()
	if h.cfg.EnableIPv4 {
		ipv4Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(false), n.GetIPv4AllocCIDRs())
		if err != nil {
			return err
		}
		routes = append(routes, ipv4Routes...)
	}
	if h.cfg.EnableIPv6 {
		ipv6Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(true), n.GetIPv6AllocCIDRs())
		if err != nil {
			return err
		}
		routes = append(routes, ipv6Routes...)
	}
	owner, err := h.routeManager.GetOrRegisterOwner(getOwnerName(nodeName))
	if err != nil {
		return fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}
	return h.routeManager.ReplaceOwnerRoutes(owner, routes)
}

func (h *Handler) processNodeChange(node *node.Node, isDeleted bool) error {
	if node.IsLocal() {
		// if the node is local, we don't need to add or remove routes for it.
		return nil
	}

	if h.nodePolicy.EnableEncapsulation(&node.Node, false) {
		// ask!: check if we really need this check
		// here we always use false because if we reach this point encapsulation should be disabled.
		// If we have an override for the encapsulation we skip the node
		return deleteNodeRoutes(h.routeManager, node.Fullname())
	}

	if isDeleted {
		return deleteNodeRoutes(h.routeManager, node.Fullname())
	}
	return h.updateNodeRoutes(node)
}

func (h *Handler) run(ctx context.Context, health cell.Health) error {
	// Wait for the nodes table to be initialized before processing changes.
	// We do this before the for loop so that after the first batch of changes
	// we are sure, we can finalize the initializer.
	// the route reconciler will delete old routes for us after an agent restart.
	finalized := false
	_, initialized := h.nodes.Initialized(h.db.ReadTxn())
	select {
	case <-ctx.Done():
		return nil
	case <-initialized:
	}

	wtxn := h.db.WriteTxn(h.nodes)
	changes, err := h.nodes.Changes(wtxn)
	if err != nil {
		wtxn.Abort()
		return fmt.Errorf("subscribing to node changes: %w", err)
	}
	wtxn.Commit()
	defer changes.Close()

	for {
		rtxn := h.db.ReadTxn()
		// ask!: what is the best strategy to handle an error on the single node.
		batch, watch := changes.Next(rtxn)

		var errs error
		for change := range batch {
			if err := h.processNodeChange(change.Object, change.Deleted); err != nil {
				errs = errors.Join(errs,
					fmt.Errorf("processing node change for %s: %w", change.Object.Fullname(), err))
			}
		}

		if !finalized {
			h.routeManager.FinalizeInitializer(h.initializer)
			finalized = true
		}

		if errs != nil {
			health.Degraded("failed to update Auto-direct-node-routes for one or more nodes", errs)
		} else {
			health.OK("Auto-direct-node-routes synchronized")
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

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
		return 0, fmt.Errorf("%w: node %q uses gateway %q",
			errNodeNotOnSameL2,
			nodeIP,
			firstRoute.Gw)
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
