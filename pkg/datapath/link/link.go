// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package link

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

// DeleteByName deletes the interface with the name ifName.
//
// Returns nil if the interface does not exist.
func DeleteByName(ifName string) error {
	iface, err := safenetlink.LinkByName(ifName)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to lookup %q: %w", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %w", ifName, err)
	}

	return nil
}

// Rename renames a network link
func Rename(curName, newName string) error {
	link, err := safenetlink.LinkByName(curName)
	if err != nil {
		return err
	}

	return netlink.LinkSetName(link, newName)
}

func GetHardwareAddr(ifName string) (mac.MAC, error) {
	iface, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return nil, err
	}
	return mac.MAC(iface.Attrs().HardwareAddr), nil
}

func GetIfIndex(ifName string) (uint32, error) {
	iface, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Attrs().Index), nil
}

type LinkCache struct {
	mu          lock.RWMutex
	indexToName map[int]string
	manager     *controller.Manager
}

var Cell = cell.Module(
	"link-cache",
	"Provides a cache of link names to ifindex mappings",

	cell.Provide(newLinkCache),
)

type linkCacheParams struct {
	cell.In
	JobGroup job.Group
}

func NewLinkCache() *LinkCache {
	return &LinkCache{
		indexToName: make(map[int]string),
		manager:     controller.NewManager(),
	}
}

func newLinkCache(params linkCacheParams) *LinkCache {
	lc := NewLinkCache()

	params.JobGroup.Add(job.Timer("sync", lc.SyncCache, 15*time.Second))

	return lc
}

func (c *LinkCache) SyncCache(_ context.Context) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return err
	}

	indexToName := make(map[int]string, len(links))
	for _, link := range links {
		indexToName[link.Attrs().Index] = link.Attrs().Name
	}

	c.mu.Lock()
	c.indexToName = indexToName
	c.mu.Unlock()
	return nil
}

func (c *LinkCache) lookupName(ifIndex int) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name, ok := c.indexToName[ifIndex]
	return name, ok
}

// GetIfNameCached returns the name of an interface (if it exists) by looking
// it up in a regularly updated cache. The return result is the same as a map
// lookup, ie nil, false if there is no entry cached for this ifindex.
func (c *LinkCache) GetIfNameCached(ifIndex int) (string, bool) {
	return c.lookupName(ifIndex)
}

// Name returns the name of a link by looking up the 'LinkCache', or returns a
// string containing the ifindex on cache miss.
func (c *LinkCache) Name(ifIndex uint32) string {
	if name, ok := c.lookupName(int(ifIndex)); ok {
		return name
	}
	return strconv.Itoa(int(ifIndex))
}
