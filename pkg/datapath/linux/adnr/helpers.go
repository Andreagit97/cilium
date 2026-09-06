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

func (h *Handler) deleteNodeRoutes(nodeName string) error {
	owner, err := h.routeManager.GetOwner(getOwnerName(nodeName))
	if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting route owner for node %s: %w", nodeName, err)
	}
	return h.routeManager.RemoveOwner(owner)
}

func (h *Handler) getNodeRoutes(nodeName string, nodeIP net.IP, podCIDRs []netip.Prefix) ([]routeReconciler.DesiredRoute, error) {
	// We check if the remote node is reachable on the same L2 Network
	index, err := getRouteIndex(nodeIP)
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

	// We know get the device associated with the index we obtained from the route.
	dev, err := getDevice(index, h.devices, h.db)
	if err != nil {
		return nil, fmt.Errorf("getting device for node %s: %w", nodeName, err)
	}

	routes := make([]routeReconciler.DesiredRoute, 0, len(podCIDRs))
	ip, _ := netip.AddrFromSlice(nodeIP)
	for _, prefix := range podCIDRs {
		routes = append(routes, routeReconciler.DesiredRoute{
			// Owner:  will be populated when converting the slice into a map
			Table:         routeReconciler.TableMain, // ask!: TableMain is ok?
			Prefix:        prefix,
			AdminDistance: routeReconciler.AdminDistanceDefault,
			Nexthop:       ip.Unmap(),
			Device:        dev,
		})
	}
	return routes, nil
}

func (h *Handler) replaceNodeRoutes(nodeName string, routes []routeReconciler.DesiredRoute) error {
	ownerName := getOwnerName(nodeName)
	owner, err := h.routeManager.GetOrRegisterOwner(ownerName)
	if err != nil {
		return fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}

	routesMap := make(map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute, len(routes))
	for _, route := range routes {
		route.Owner = owner
		routesMap[route.GetFullKey()] = route
	}
	return h.routeManager.ReplaceOwnerRoutes(owner, routesMap)
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
	return h.replaceNodeRoutes(nodeName, routes)
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
		return h.deleteNodeRoutes(node.Fullname())
	}

	if isDeleted {
		return h.deleteNodeRoutes(node.Fullname())
	}
	return h.updateNodeRoutes(node)
}

func (h *Handler) run(ctx context.Context, health cell.Health) error {
	wtxn := h.db.WriteTxn(h.nodes)
	changes, err := h.nodes.Changes(wtxn)
	if err != nil {
		wtxn.Abort()
		return fmt.Errorf("subscribing to node changes: %w", err)
	}
	wtxn.Commit()

	for {
		rtxn := h.db.ReadTxn()
		// todo!: is there a way to retry for a node, in case of error?
		// todo!: if a node goes down or is deleted while the agent is restarting we don't delete its routes properly.
		batch, watch := changes.Next(rtxn)

		var errs error
		for change := range batch {
			if err := h.processNodeChange(change.Object, change.Deleted); err != nil {
				errs = fmt.Errorf("processing node change for %s: %w", change.Object.Fullname(), err)
			}
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

// todo!: we can share the helper with the endpoint route logic
// https://github.com/cilium/cilium/blob/e31fcdb45424acf822950591e4bc39092492c312/pkg/datapath/loader/endpoint.go#L315
func getDevice(index int, devices statedb.Table[*tables.Device], db *statedb.DB) (*tables.Device, error) {
	const devTableWaitTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), devTableWaitTimeout)
	defer cancel()

	var epDev *tables.Device
	for {
		var found bool
		var watch <-chan struct{}
		epDev, _, watch, found = devices.GetWatch(db.ReadTxn(), tables.DeviceByIndex(index))
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
