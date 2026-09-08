// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/cilium/cilium/pkg/time"
)

func TestGetDevice(t *testing.T) {
	t.Parallel()

	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)

	// insert a device
	deviceIndex := 10
	device := &tables.Device{
		Index: deviceIndex,
	}
	insertTestDevice(t, db, devices, device)

	t.Run("existing_device", func(t *testing.T) {
		t.Parallel()
		dev, err := getDevice(deviceIndex, devices.ToTable(), db, 2*time.Second)
		require.NoError(t, err)
		require.Equal(t, device, dev)
	})

	t.Run("non_existent_device", func(t *testing.T) {
		t.Parallel()
		nonExistentDeviceIndex := 999
		dev, err := getDevice(nonExistentDeviceIndex, devices.ToTable(), db, 300*time.Millisecond)
		require.Error(t, err)
		require.Nil(t, dev)
	})
}

func TestPrivilegedGetRouteIndex(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	var dummyIndex int

	const (
		hostIPV4           = "172.19.0.1"
		peerSameNetIPV4    = "172.19.0.2"
		gatewayIPV4        = "172.19.0.254"
		gatewayDstIPV4     = "172.19.2.0/24"
		peerGatewayNetIPV4 = "172.19.2.2"
		peerExternalIPV4   = "10.0.0.1"

		hostIPV6           = "2001:db8:1::1"
		peerSameNetIPV6    = "2001:db8:1::2"
		gatewayIPV6        = "2001:db8:1::fe"
		gatewayDstIPV6     = "2001:db8:2::/64"
		peerGatewayNetIPV6 = "2001:db8:2::2"
		peerExternalIPV6   = "2001:db8:ffff::10"
	)

	// Setup the network namespace and dummy interface for testing routes
	ns.Do(func() error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "adnr-test"}}
		require.NoError(t, netlink.LinkAdd(dummy))

		link, err := safenetlink.LinkByName(dummy.Name)
		require.NoError(t, err)

		dummyIndex = link.Attrs().Index

		// We setup the dummy network interface so that we can add a route.
		require.NoError(t, netlink.LinkSetUp(link))

		// Assign an IP address to the dummy interface
		// This will create a route:
		// 172.19.0.0/24 dev adnr-test proto kernel
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/24", hostIPV4))
		require.NoError(t, err)
		require.NoError(t, netlink.AddrAdd(link, addr))
		addr, err = netlink.ParseAddr(fmt.Sprintf("%s/64", hostIPV6))
		require.NoError(t, err)
		require.NoError(t, netlink.AddrAdd(link, addr))

		_, gatewayDst, err := net.ParseCIDR(gatewayDstIPV4)
		require.NoError(t, err)
		require.NoError(t, netlink.RouteReplace(&netlink.Route{
			LinkIndex: dummyIndex,
			Gw:        net.ParseIP(gatewayIPV4),
			Dst:       gatewayDst,
		}))
		_, gatewayDst, err = net.ParseCIDR(gatewayDstIPV6)
		require.NoError(t, err)
		require.NoError(t, netlink.RouteReplace(&netlink.Route{
			LinkIndex: dummyIndex,
			Gw:        net.ParseIP(gatewayIPV6),
			Dst:       gatewayDst,
			Flags:     int(netlink.FLAG_ONLINK),
		}))

		// Show the routing setup before starting tests
		list, err := safenetlink.RouteList(link, netlink.FAMILY_V4)
		require.NoError(t, err)
		for _, route := range list {
			t.Logf("IPV4 route: %+v", route)
		}
		list6, err := safenetlink.RouteList(link, netlink.FAMILY_V6)
		require.NoError(t, err)
		for _, route := range list6 {
			t.Logf("IPV6 route: %+v", route)
		}
		return nil
	})

	tests := []struct {
		name       string
		ip         string
		assertFunc func(t *testing.T, index int, err error)
	}{
		{
			name: "existing_route_ipv4",
			ip:   peerSameNetIPV4,
			assertFunc: func(t *testing.T, index int, err error) {
				require.NoError(t, err)
				require.Equal(t, dummyIndex, index)
			},
		},
		{
			name: "non_existing_route_ipv4",
			ip:   peerExternalIPV4,
			assertFunc: func(t *testing.T, index int, err error) {
				require.Error(t, err)
				require.Zero(t, index)
			},
		},
		{
			name: "gateway_ipv4",
			ip:   peerGatewayNetIPV4,
			assertFunc: func(t *testing.T, index int, err error) {
				require.Error(t, err)
				require.Zero(t, index)
				require.ErrorIs(t, err, errNodeNotOnSameL2)
			},
		},
		{
			name: "loopback_ipv4",
			ip:   hostIPV4,
			assertFunc: func(t *testing.T, index int, err error) {
				require.NoError(t, err)
				require.Equal(t, dummyIndex, index)
			},
		},
		{
			name: "existing_route_ipv6",
			ip:   hostIPV6,
			assertFunc: func(t *testing.T, index int, err error) {
				require.NoError(t, err)
				require.Equal(t, dummyIndex, index)
			},
		},
		{
			name: "non_existing_route_ipv6",
			ip:   peerExternalIPV6,
			assertFunc: func(t *testing.T, index int, err error) {
				require.Error(t, err)
				require.Zero(t, index)
			},
		},
		{
			name: "gateway_ipv6",
			ip:   peerGatewayNetIPV6,
			assertFunc: func(t *testing.T, index int, err error) {
				require.Error(t, err)
				require.Zero(t, index)
				require.ErrorIs(t, err, errNodeNotOnSameL2)
			},
		},
		{
			name: "loopback_ipv6",
			ip:   hostIPV6,
			assertFunc: func(t *testing.T, index int, err error) {
				require.NoError(t, err)
				require.Equal(t, dummyIndex, index)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns.Do(func() error {
				index, err := getRouteIndex(net.ParseIP(tt.ip))
				tt.assertFunc(t, index, err)
				return nil
			})
		})
	}
}
