// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
)

func TestUpsertRoute(t *testing.T) {
	db := statedb.New()
	tbl, err := newDesiredRouteTable(db)
	require.NoError(t, err)

	manager := newDesiredRouteManager(db, tbl, nil)
	owner1, err := manager.RegisterOwner("owner1")
	require.NoError(t, err)

	route := DesiredRoute{
		Owner:         owner1,
		Prefix:        netip.MustParsePrefix("10.0.0.1/32"),
		AdminDistance: AdminDistanceDefault,
		Table:         TableMain,
		Priority:      1,
	}
	require.NoError(t, manager.UpsertRoute(route))

	// After the upsert the route should be selected and be in pending state waiting for reconciliation.
	keyOwner1 := route.GetFullKey()
	stored, _, found := tbl.Get(db.ReadTxn(), DesiredRouteIndex.Query(keyOwner1))
	require.True(t, found)
	require.Equal(t, TableMain, stored.Table)
	require.Equal(t, route.Prefix, stored.Prefix)
	require.Equal(t, AdminDistanceDefault, stored.AdminDistance)
	require.True(t, stored.selected)
	require.Equal(t, reconciler.StatusKindPending, stored.GetStatus().Kind)

	// We now create a new route with the same ownerless key but with a different owner.
	owner0, err := manager.RegisterOwner("owner0")
	require.NoError(t, err)
	route = DesiredRoute{
		Owner:         owner0,
		Prefix:        netip.MustParsePrefix("10.0.0.1/32"),
		AdminDistance: AdminDistanceDefault,
		Table:         TableMain,
		Priority:      1,
	}
	require.NoError(t, manager.UpsertRoute(route))

	keyOwner0 := route.GetFullKey()
	stored, _, found = tbl.Get(db.ReadTxn(), DesiredRouteIndex.Query(keyOwner0))
	require.True(t, found)
	require.True(t, stored.selected)
	require.Equal(t, reconciler.StatusKindPending, stored.GetStatus().Kind)

	// The route with owner1 should still be present but not selected.
	stored, _, found = tbl.Get(db.ReadTxn(), DesiredRouteIndex.Query(keyOwner1))
	require.True(t, found)
	require.False(t, stored.selected)
	require.Equal(t, reconciler.StatusKindPending, stored.GetStatus().Kind)
}

func assertRoutes(t *testing.T, db *statedb.DB, tbl statedb.RWTable[*DesiredRoute], expectedRoutes []DesiredRoute) {
	t.Helper()
	routes := slices.Collect(statedb.ToSeq(tbl.All(db.ReadTxn())))
	// the length should be the same
	require.Len(t, routes, len(expectedRoutes))
	actualRoutes := make([]DesiredRoute, 0, len(routes))
	for _, route := range routes {
		// all routes in the table should be selected and in pending status
		require.True(t, route.selected)
		require.Equal(t, reconciler.StatusKindPending, route.GetStatus().Kind)
		actual := *route
		// we clear those fields to make the comparison with expectedRoutes easier
		actual.selected = false
		actual.status = reconciler.Status{}
		actualRoutes = append(actualRoutes, actual)
	}

	require.ElementsMatch(t, expectedRoutes, actualRoutes)
}

func TestReplaceOwnerRoutes(t *testing.T) {
	baseIPV4 := netip.MustParseAddr("192.0.1.2")
	baseIPV6 := netip.MustParseAddr("fd00::2")
	baseIPV4Prefix := netip.MustParsePrefix("10.10.2.0/24")
	baseIPV6Prefix := netip.MustParsePrefix("fd00:10:10:2::/64")
	baseDevIndex := 10

	newIPV4 := netip.MustParseAddr("192.0.1.3")
	newIPV6 := netip.MustParseAddr("fd00::3")
	newIPV4Prefix := netip.MustParsePrefix("10.10.3.0/24")
	newIPV6Prefix := netip.MustParsePrefix("fd00:10:10:3::/64")
	newDevIndex := 11

	newRouteWithoutOwner := func(
		prefix netip.Prefix,
		nexthop netip.Addr,
		deviceIdx int,
	) DesiredRoute {
		return DesiredRoute{
			Owner:         nil,
			Prefix:        prefix,
			AdminDistance: AdminDistanceDefault,
			Table:         TableMain,
			Nexthop:       nexthop,
			Device: &tables.Device{
				Index: deviceIdx,
			},
		}
	}

	baseRoutes := []DesiredRoute{
		newRouteWithoutOwner(baseIPV4Prefix, baseIPV4, baseDevIndex),
		newRouteWithoutOwner(baseIPV6Prefix, baseIPV6, baseDevIndex),
	}

	tests := []struct {
		name     string
		initial  []DesiredRoute
		replaced []DesiredRoute
	}{
		{
			name:     "adds_routes",
			initial:  []DesiredRoute{},
			replaced: baseRoutes,
		},
		{
			name:     "removes_routes",
			initial:  baseRoutes,
			replaced: []DesiredRoute{},
		},
		{
			name:    "changes_prefix",
			initial: baseRoutes,
			replaced: []DesiredRoute{
				newRouteWithoutOwner(newIPV4Prefix, newIPV4, baseDevIndex),
				newRouteWithoutOwner(newIPV6Prefix, newIPV6, baseDevIndex),
			},
		},
		{
			name:    "changes_nexthop_and_device",
			initial: baseRoutes,
			replaced: []DesiredRoute{
				newRouteWithoutOwner(baseIPV4Prefix, newIPV4, newDevIndex),
				newRouteWithoutOwner(baseIPV6Prefix, newIPV6, newDevIndex),
			},
		},
		{
			name:    "add_new_route",
			initial: baseRoutes,
			replaced: append([]DesiredRoute{
				newRouteWithoutOwner(newIPV4Prefix, newIPV4, newDevIndex),
			}, baseRoutes...),
		},
		{
			name:    "add_stale_route",
			initial: baseRoutes,
			replaced: []DesiredRoute{
				newRouteWithoutOwner(newIPV4Prefix, newIPV4, newDevIndex),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := statedb.New()
			tbl, err := newDesiredRouteTable(db)
			require.NoError(t, err)
			manager := newDesiredRouteManager(db, tbl, nil)

			owner, err := manager.RegisterOwner("exampleOwner")
			require.NoError(t, err)

			// We add the owner to our input slices
			for i := range tt.initial {
				tt.initial[i].Owner = owner
			}
			for i := range tt.replaced {
				tt.replaced[i].Owner = owner
			}

			require.NoError(t, manager.ReplaceOwnerRoutes(owner, tt.initial))
			require.Len(t, slices.Collect(statedb.ToSeq(tbl.All(db.ReadTxn()))), len(tt.initial))

			require.NoError(t, manager.ReplaceOwnerRoutes(owner, tt.replaced))
			assertRoutes(t, db, tbl, tt.replaced)

		})
	}
}
