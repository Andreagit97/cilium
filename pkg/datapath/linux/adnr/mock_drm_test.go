package adnr

import routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"

type mockDesiredRouteManager struct {
	owners map[string]*routeReconciler.RouteOwner
	routes map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute
}

func newMockDesiredRouteManager() *mockDesiredRouteManager {
	return &mockDesiredRouteManager{
		owners: make(map[string]*routeReconciler.RouteOwner),
		routes: make(map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute),
	}
}

func (m *mockDesiredRouteManager) GetOrRegisterOwner(name string) (*routeReconciler.RouteOwner, error) {
	owner := &routeReconciler.RouteOwner{}
	m.owners[name] = owner
	return owner, nil
}

func (m *mockDesiredRouteManager) ReplaceOwnerRoutes(owner *routeReconciler.RouteOwner, newRoutes map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute) error {
	return nil
}

func (m *mockDesiredRouteManager) RegisterInitializer(name string) routeReconciler.Initializer {
	return routeReconciler.Initializer{}
}

func (m *mockDesiredRouteManager) GetOwner(name string) (*routeReconciler.RouteOwner, error) {
	if owner, ok := m.owners[name]; ok {
		return owner, nil
	}
	return nil, routeReconciler.ErrOwnerDoesNotExist
}

func (m *mockDesiredRouteManager) RemoveOwner(owner *routeReconciler.RouteOwner) error {
	if owner == nil {
		return routeReconciler.ErrOwnerDoesNotExist
	}
	return nil
}
