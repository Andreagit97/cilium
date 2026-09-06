// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/linux"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// desiredRouteManager is an interface that abstracts the routeReconciler.DesiredRouteManager
// provides a mockable interface for testing purposes.
// type desiredRouteManager interface {
// 	GetOrRegisterOwner(string) (*routeReconciler.RouteOwner, error)
// 	ReplaceOwnerRoutes(
// 		*routeReconciler.RouteOwner,
// 		map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute,
// 	) error
// 	RegisterInitializer(name string) routeReconciler.Initializer
// 	GetOwner(string) (*routeReconciler.RouteOwner, error)
// 	RemoveOwner(*routeReconciler.RouteOwner) error
// }

var Cell = cell.Module(
	"auto-direct-node-routes",
	"Maintains direct routes to remote node PodCIDRs",
	cell.Invoke(RegisterHandler),
)

type Params struct {
	cell.In

	DB           *statedb.DB
	Nodes        statedb.Table[*node.Node]
	Devices      statedb.Table[*tables.Device]
	RouteManager *routeReconciler.DesiredRouteManager
	DaemonConfig *option.DaemonConfig
	NodePolicy   *linux.NodePolicy
	JobGroup     job.Group
	Logger       *slog.Logger
}

func RegisterHandler(params Params) {
	if !params.DaemonConfig.EnableAutoDirectRouting {
		return
	}

	h := &Handler{
		db:            params.DB,
		nodes:         params.Nodes,
		devices:       params.Devices,
		routeManager:  params.RouteManager,
		getRouteIndex: getRouteIndex,
		nodePolicy:    params.NodePolicy,
		initializer:   params.RouteManager.RegisterInitializer("adnr"),
		cfg:           params.DaemonConfig,
		logger:        params.Logger,
	}

	params.JobGroup.Add(job.OneShot(
		"auto-direct-node-routes",
		h.run,
		job.WithRetry(-1, &job.ExponentialBackoff{
			Min: 100 * time.Millisecond,
			Max: time.Minute,
		}),
	))
}

// Handler handles auto-direct-node-routes creation and deletion.
type Handler struct {
	db            *statedb.DB
	nodes         statedb.Table[*node.Node]
	devices       statedb.Table[*tables.Device]
	routeManager  *routeReconciler.DesiredRouteManager
	getRouteIndex func(net.IP) (int, error)
	nodePolicy    *linux.NodePolicy
	initializer   routeReconciler.Initializer
	cfg           *option.DaemonConfig
	logger        *slog.Logger
}
