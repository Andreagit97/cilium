// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"log/slog"

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
		db:           params.DB,
		nodes:        params.Nodes,
		devices:      params.Devices,
		routeManager: params.RouteManager,
		nodePolicy:   params.NodePolicy,
		initializer:  params.RouteManager.RegisterInitializer("adnr"),
		cfg:          params.DaemonConfig,
		logger:       params.Logger,
	}

	params.JobGroup.Add(job.OneShot(
		"auto-direct-node-routes",
		h.run,
		// todo!: check what other components do for the backoff and health checks
		job.WithRetry(-1, &job.ExponentialBackoff{
			Min: 100 * time.Millisecond,
			Max: time.Minute,
		}),
	))
}

// Handler handles auto-direct-node-routes creation and deletion.
type Handler struct {
	db           *statedb.DB
	nodes        statedb.Table[*node.Node]
	devices      statedb.Table[*tables.Device]
	routeManager *routeReconciler.DesiredRouteManager
	nodePolicy   *linux.NodePolicy
	initializer  routeReconciler.Initializer
	cfg          *option.DaemonConfig
	logger       *slog.Logger
}
