// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
)

func TestDesiredRouteManagerUpsertRoute(t *testing.T) {
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

	// we now create a new route with the same ownwerless key but with a different owner
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

	// After the upsert of the route with owner0, it should be selected and be in pending state waiting for reconciliation.
	keyOwner0 := route.GetFullKey()
	stored, _, found = tbl.Get(db.ReadTxn(), DesiredRouteIndex.Query(keyOwner0))
	require.True(t, found)
	require.True(t, stored.selected)
	require.Equal(t, reconciler.StatusKindPending, stored.GetStatus().Kind)

	// the route with owner1 should still be present but not selected.
	stored, _, found = tbl.Get(db.ReadTxn(), DesiredRouteIndex.Query(keyOwner1))
	require.True(t, found)
	require.False(t, stored.selected)
	require.Equal(t, reconciler.StatusKindPending, stored.GetStatus().Kind)
}
