// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

// import (
// 	"context"
// 	"fmt"
// 	"net"
// 	"net/netip"
// 	"slices"
// 	"strings"
// 	"testing"

// 	"github.com/cilium/hive/cell"
// 	"github.com/cilium/hive/hivetest"
// 	"github.com/cilium/statedb"
// 	"github.com/stretchr/testify/require"

// 	"github.com/cilium/cilium/pkg/datapath/linux"
// 	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
// 	"github.com/cilium/cilium/pkg/datapath/tables"
// 	"github.com/cilium/cilium/pkg/hive"
// 	"github.com/cilium/cilium/pkg/node"
// 	"github.com/cilium/cilium/pkg/node/addressing"
// 	"github.com/cilium/cilium/pkg/node/types"
// 	nodeTypes "github.com/cilium/cilium/pkg/node/types"
// 	"github.com/cilium/cilium/pkg/option"
// )

// func newCiliumNode(name, ip, cidr string) *node.Node {
// 	return &node.Node{Node: nodeTypes.Node{
// 		Name: name,
// 		IPAddresses: []nodeTypes.Address{{
// 			Type: addressing.NodeInternalIP,
// 			IP:   net.ParseIP(ip),
// 		}},
// 		IPv4AllocCIDR: nodeTypes.PrefixFrom(netip.MustParsePrefix(cidr)),
// 	}}
// }

// func TestADRNFullFlow(t *testing.T) {
// 	/////////////////////
// 	// Scaffold test variables
// 	/////////////////////
// 	var (
// 		db            *statedb.DB
// 		nodes         statedb.RWTable[*node.Node]
// 		devices       statedb.RWTable[*tables.Device]
// 		desiredRoutes statedb.Table[*routeReconciler.DesiredRoute]
// 		routeManager  *routeReconciler.DesiredRouteManager
// 	)

// 	h := hive.New(
// 		cell.Provide(
// 			node.NewNodeTable,
// 			statedb.RWTable[*node.Node].ToTable,
// 			tables.NewDeviceTable,
// 			statedb.RWTable[*tables.Device].ToTable,
// 			func() *option.DaemonConfig {
// 				return &option.DaemonConfig{
// 					StateDir: t.TempDir(),
// 				}
// 			},
// 			// this route table is needed by the routeReconciler
// 			tables.NewRouteTable,
// 			statedb.RWTable[*tables.Route].ToTable,
// 		),
// 		routeReconciler.Cell,
// 		cell.Invoke(func(
// 			db_ *statedb.DB,
// 			nodes_ statedb.RWTable[*node.Node],
// 			devices_ statedb.RWTable[*tables.Device],
// 			desiredRoutes_ statedb.Table[*routeReconciler.DesiredRoute],
// 			routeManager_ *routeReconciler.DesiredRouteManager,
// 		) {
// 			db = db_
// 			nodes = nodes_
// 			devices = devices_
// 			desiredRoutes = desiredRoutes_
// 			routeManager = routeManager_
// 		}),
// 	)
// 	require.NoError(t, h.Populate(hivetest.Logger(t)))

// 	handler := &Handler{
// 		db:           db,
// 		nodes:        nodes,
// 		devices:      devices,
// 		routeManager: routeManager,
// 		nodePolicy:   &linux.NodePolicy{},
// 		cfg: &option.DaemonConfig{
// 			EnableIPv4:                   true,
// 			DirectRoutingSkipUnreachable: false,
// 		},
// 		logger: hivetest.Logger(t),
// 	}

// 	/////////////////////
// 	// Fill tables before running the handler
// 	/////////////////////

// 	// this is the node where the ADRN handler is running (local node)
// 	// we shouldn't create a route for it.
// 	localNodeName := "local-node"
// 	types.SetName(localNodeName)
// 	localNode := newCiliumNode("local-node", "192.0.1.10", "10.0.1.0/24")

// 	node1IP := "192.0.1.11"
// 	node1Name := "remote-node-1"
// 	node1Prefix := "10.0.2.0/24"
// 	node1DeviceIndex := 10
// 	node1 := newCiliumNode(node1Name, node1IP, node1Prefix)

// 	node2IP := "192.0.1.12"
// 	node2Name := "remote-node-2"
// 	node2Prefix := "10.0.3.0/24"
// 	node2DeviceIndex := 11
// 	node2 := newCiliumNode(node2Name, node2IP, node2Prefix)

// 	// this is a node in a different LAN
// 	// we shouldn't create a route for it.
// 	extNodeIP := "192.0.2.1"
// 	extNodeName := "different-lan-node"
// 	extNodePrefix := "10.0.4.0/24"
// 	extNode := newCiliumNode(extNodeName, extNodeIP, extNodePrefix)

// 	// Add nodes to the table
// 	txn := db.WriteTxn(nodes)
// 	for _, n := range []*node.Node{localNode, node1, node2, extNode} {
// 		_, _, err := nodes.Insert(txn, n)
// 		require.NoError(t, err)
// 	}
// 	txn.Commit()

// 	// Populate the device we will use to reach the nodes
// 	txn = db.WriteTxn(devices)
// 	device1 := &tables.Device{
// 		Index: node1DeviceIndex,
// 	}
// 	device2 := &tables.Device{
// 		Index: node2DeviceIndex,
// 	}
// 	for _, n := range []*tables.Device{device1, device2} {
// 		_, _, err := devices.Insert(txn, n)
// 		require.NoError(t, err)
// 	}
// 	txn.Commit()

// 	handler.getRouteIndex = func(ip net.IP) (int, error) {
// 		switch ip.String() {
// 		case node1IP:
// 			return node1DeviceIndex, nil
// 		case node2IP:
// 			return node2DeviceIndex, nil
// 		case extNodeIP:
// 			return 0, errNodeNotOnSameL2
// 		default:
// 			return 0, fmt.Errorf("no route found for IP %s", ip.String())
// 		}
// 	}

// 	/////////////////////
// 	// Running handler and assert routes
// 	/////////////////////

// 	ctx, cancel := context.WithCancel(t.Context())
// 	health, healthState := cell.NewSimpleHealth()
// 	runResult := make(chan error, 1)
// 	go func() {
// 		runResult <- handler.run(ctx, health)
// 	}()

// 	// we immediately cancel the context and when it returns we are sure routes are created.
// 	cancel()
// 	require.NoError(t, <-runResult)

// 	// The health state should be ok
// 	require.NoError(t, healthState.Error)
// 	require.Equal(t, cell.StatusOK, healthState.Level)

// 	ownerNode1, err := routeManager.GetOwner(getOwnerName(node1Name))
// 	require.NoError(t, err)
// 	require.NotNil(t, ownerNode1)

// 	ownerNode2, err := routeManager.GetOwner(getOwnerName(node2Name))
// 	require.NoError(t, err)
// 	require.NotNil(t, ownerNode2)

// 	// We expect two routes to be created
// 	routes := slices.Collect(statedb.ToSeq(desiredRoutes.All(db.ReadTxn())))
// 	require.Len(t, routes, 2)
// 	slices.SortFunc(routes, func(a, b *routeReconciler.DesiredRoute) int {
// 		return strings.Compare(a.Owner.String(), b.Owner.String())
// 	})
// 	owner1Route := routes[0]
// 	owner2Route := routes[1]
// 	require.Equal(t, ownerNode1, owner1Route.Owner)
// 	require.Equal(t, netip.MustParsePrefix(node1Prefix), owner1Route.Prefix)
// 	require.Equal(t, netip.MustParseAddr(node1IP), owner1Route.Nexthop)
// 	require.Equal(t, device1, owner1Route.Device)
// 	require.Equal(t, routeReconciler.TableMain, owner1Route.Table)
// 	require.Equal(t, routeReconciler.AdminDistanceDefault, owner1Route.AdminDistance)

// 	require.Equal(t, ownerNode2, owner2Route.Owner)
// 	require.Equal(t, netip.MustParsePrefix(node2Prefix), owner2Route.Prefix)
// 	require.Equal(t, netip.MustParseAddr(node2IP), owner2Route.Nexthop)
// 	require.Equal(t, routeReconciler.TableMain, owner2Route.Table)
// 	require.Equal(t, routeReconciler.AdminDistanceDefault, owner2Route.AdminDistance)
// 	require.Equal(t, device2, owner2Route.Device)
// }
