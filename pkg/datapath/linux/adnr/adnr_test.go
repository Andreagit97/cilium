// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/datapath/linux"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func newCiliumNode(name, ip, cidr string) *node.Node {
	return &node.Node{Node: nodeTypes.Node{
		Name: name,
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP(ip),
		}},
		IPv4AllocCIDR: nodeTypes.PrefixFrom(netip.MustParsePrefix(cidr)),
	}}
}

func insertTestNode(t testing.TB, db *statedb.DB, nodes statedb.RWTable[*node.Node], n *node.Node) {
	t.Helper()
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
}

func insertTestDevice(t testing.TB, db *statedb.DB, devices statedb.RWTable[*tables.Device], d *tables.Device) {
	t.Helper()
	txn := db.WriteTxn(devices)
	_, _, err := devices.Insert(txn, d)
	require.NoError(t, err)
	txn.Commit()
}

func newTestDesiredRouteManagerSetup(t testing.TB) (
	*statedb.DB,
	statedb.Table[*routeReconciler.DesiredRoute],
	*routeReconciler.DesiredRouteManager,
) {
	t.Helper()
	var (
		routeManager  *routeReconciler.DesiredRouteManager
		desiredRoutes statedb.Table[*routeReconciler.DesiredRoute]
		db            *statedb.DB
	)
	hive.New(
		routeReconciler.TableCell,
		cell.Provide(func() reconciler.Reconciler[*routeReconciler.DesiredRoute] {
			return nil
		}),
		cell.Invoke(func(
			db_ *statedb.DB,
			routes statedb.Table[*routeReconciler.DesiredRoute],
			manager *routeReconciler.DesiredRouteManager,
		) {
			db = db_
			desiredRoutes = routes
			routeManager = manager
		}),
	).Populate(hivetest.Logger(t))
	return db, desiredRoutes, routeManager
}

func TestDeleteNodeRoutes(t *testing.T) {
	db, desiredRoutes, rm := newTestDesiredRouteManagerSetup(t)

	// Create a route for the node
	nodeName := "node1"
	owner, err := rm.GetOrRegisterOwner(getOwnerName(nodeName))
	require.NoError(t, err)
	rm.UpsertRoute(routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        netip.MustParsePrefix("192.168.1.0/24"),
		AdminDistance: routeReconciler.AdminDistanceDefault,
	})
	routes := slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
	require.Len(t, routes, 1)

	// No error on deletion
	require.NoError(t, deleteNodeRoutes(rm, nodeName))
	// We should not find entries after the deletion
	routes = slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
	require.Len(t, routes, 0)

	// remove a non-existent owner should return nil
	require.Nil(t, deleteNodeRoutes(rm, "not-exist"))
}

// todo!: test getDevice
// todo!: test getRouteIndex using a privileged test

func TestADRNFullFlow(t *testing.T) {
	db, desiredRoutes, rm := newTestDesiredRouteManagerSetup(t)

	/////////////////////
	// Populate node table
	/////////////////////

	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	localNodeName := "local-node"
	types.SetName(localNodeName)
	localNode := newCiliumNode("local-node", "192.0.1.10", "10.0.1.0/24")

	node1IP := "192.0.1.11"
	node1Name := "remote-node-1"
	node1Prefix := "10.0.2.0/24"
	node1DeviceIndex := 10
	node1 := newCiliumNode(node1Name, node1IP, node1Prefix)

	node2IP := "192.0.1.12"
	node2Name := "remote-node-2"
	node2Prefix := "10.0.3.0/24"
	node2DeviceIndex := 11
	node2 := newCiliumNode(node2Name, node2IP, node2Prefix)

	// this is a node in a different LAN
	// we shouldn't create a route for it.
	extNodeIP := "192.0.2.1"
	extNodeName := "different-lan-node"
	extNodePrefix := "10.0.4.0/24"
	extNode := newCiliumNode(extNodeName, extNodeIP, extNodePrefix)

	for _, n := range []*node.Node{localNode, node1, node2, extNode} {
		insertTestNode(t, db, nodes, n)
	}

	/////////////////////
	// Populate device table
	/////////////////////

	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)

	device1 := &tables.Device{
		Index: node1DeviceIndex,
	}
	device2 := &tables.Device{
		Index: node2DeviceIndex,
	}
	for _, n := range []*tables.Device{device1, device2} {
		insertTestDevice(t, db, devices, n)
	}

	/////////////////////
	// Setup ADNR handler
	/////////////////////

	handler := &Handler{
		db:           db,
		nodes:        nodes.ToTable(),
		devices:      devices.ToTable(),
		routeManager: rm,
		nodePolicy:   &linux.NodePolicy{},
		cfg: &option.DaemonConfig{
			EnableIPv4:                   true,
			DirectRoutingSkipUnreachable: true,
		},
		logger: hivetest.Logger(t),
	}

	handler.getRouteIndex = func(ip net.IP) (int, error) {
		switch ip.String() {
		case node1IP:
			return node1DeviceIndex, nil
		case node2IP:
			return node2DeviceIndex, nil
		case extNodeIP:
			return 0, errNodeNotOnSameL2
		default:
			return 0, fmt.Errorf("no route found for IP %s", ip.String())
		}
	}

	/////////////////////
	// Running handler and assert routes
	/////////////////////

	ctx, cancel := context.WithCancel(t.Context())
	health, healthState := cell.NewSimpleHealth()
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return handler.run(ctx, health)
	})

	require.Eventually(t, func() bool {
		return healthState.Level == cell.StatusOK
	}, time.Second*1, time.Millisecond*100)

	// we stop the handler by canceling the context and we expect no errors.
	cancel()
	require.NoError(t, g.Wait())

	ownerNode1, err := rm.GetOwner(getOwnerName(node1Name))
	require.NoError(t, err)
	require.NotNil(t, ownerNode1)

	ownerNode2, err := rm.GetOwner(getOwnerName(node2Name))
	require.NoError(t, err)
	require.NotNil(t, ownerNode2)

	// We expect two routes to be created
	routes := slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
	require.Len(t, routes, 2)
	slices.SortFunc(routes, func(a, b *routeReconciler.DesiredRoute) int {
		return strings.Compare(a.Owner.String(), b.Owner.String())
	})
	owner1Route := routes[0]
	owner2Route := routes[1]
	require.Equal(t, ownerNode1, owner1Route.Owner)
	require.Equal(t, netip.MustParsePrefix(node1Prefix), owner1Route.Prefix)
	require.Equal(t, netip.MustParseAddr(node1IP), owner1Route.Nexthop)
	require.Equal(t, device1, owner1Route.Device)
	require.Equal(t, routeReconciler.TableMain, owner1Route.Table)
	require.Equal(t, routeReconciler.AdminDistanceDefault, owner1Route.AdminDistance)

	require.Equal(t, ownerNode2, owner2Route.Owner)
	require.Equal(t, netip.MustParsePrefix(node2Prefix), owner2Route.Prefix)
	require.Equal(t, netip.MustParseAddr(node2IP), owner2Route.Nexthop)
	require.Equal(t, routeReconciler.TableMain, owner2Route.Table)
	require.Equal(t, routeReconciler.AdminDistanceDefault, owner2Route.AdminDistance)
	require.Equal(t, device2, owner2Route.Device)
}
