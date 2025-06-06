// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
)

const (
	LongTimeout  = 5 * time.Minute
	ShortTimeout = 30 * time.Second

	PollInterval = 1 * time.Second
)

// WaitForDeployment waits until the specified deployment becomes ready.
func WaitForDeployment(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) error {
	log.Logf("⌛ [%s] Waiting for deployment %s/%s to become ready...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, LongTimeout)
	defer cancel()
	for {
		err := client.CheckDeploymentStatus(ctx, namespace, name)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Deployment %s/%s is not yet ready: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for deployment %s/%s to become ready (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForDaemonSet waits until the specified daemonset becomes ready.
func WaitForDaemonSet(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) error {
	log.Logf("⌛ [%s] Waiting for DaemonSet %s/%s to become ready...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, LongTimeout)
	defer cancel()
	for {
		err := client.CheckDaemonSetStatus(ctx, namespace, name)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] DaemonSet %s/%s is not yet ready: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for DaemonSet %s/%s to become ready (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForPodDNS waits until src can query the DNS server on dst successfully.
func WaitForPodDNS(ctx context.Context, log Logger, src, dst Pod) error {
	log.Logf("⌛ [%s] Waiting for pod %s to reach DNS server on %s pod...",
		src.K8sClient.ClusterName(), src.Name(), dst.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		// We don't care about the actual response content, we just want to check the DNS operativity.
		// Since the coreDNS test server has been deployed with the "local" plugin enabled,
		// we query it with a so-called "local request" (e.g. "localhost") to get a response.
		// See https://coredns.io/plugins/local/ for more info.
		target := "localhost"
		stdout, err := src.K8sClient.ExecInPod(ctx, src.Namespace(), src.NameWithoutNamespace(),
			"", []string{"nslookup", target, dst.Address(features.IPFamilyAny)})

		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error looking up %s from pod %s to server on pod %s: %s: %s",
			src.K8sClient.ClusterName(), target, src.Name(), dst.Name(), err, stdout.String())

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for lookup for %s from pod %s to server on pod %s to succeed (last error: %w)",
				target, src.Name(), dst.Name(), err,
			)
		}
	}
}

// WaitForCoreDNS waits until the client pod can reach coredns.
func WaitForCoreDNS(ctx context.Context, log Logger, client Pod) error {
	log.Logf("⌛ [%s] Waiting for pod %s to reach default/kubernetes service...",
		client.K8sClient.ClusterName(), client.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		target := "kubernetes.default"
		stdout, err := client.K8sClient.ExecInPod(ctx, client.Namespace(), client.NameWithoutNamespace(),
			"", []string{"nslookup", target})
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error looking up %s from pod %s: %s: %s",
			client.K8sClient.ClusterName(), target, client.Name(), err, stdout.String())

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for lookup for %s from pod %s to succeed (last error: %w)",
				target, client.Name(), err)
		}
	}
}

// Service waits until the specified service is created and can be retrieved.
func WaitForServiceRetrieval(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) (Service, error) {
	log.Logf("⌛ [%s] Retrieving service %s/%s ...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		svc, err := client.GetService(ctx, namespace, name, metav1.GetOptions{})
		if err == nil {
			return Service{Service: svc.DeepCopy()}, nil
		}

		log.Debugf("[%s] Failed to retrieve Service %s/%s: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return Service{}, fmt.Errorf("timeout reached waiting for service %s/%s to be retrieved (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForService waits until the given service is synchronized in CoreDNS.
func WaitForService(ctx context.Context, log Logger, client Pod, service Service) error {
	log.Logf("⌛ [%s] Waiting for Service %s to become ready...", client.K8sClient.ClusterName(), service.Name())

	ctx, cancel := context.WithTimeout(ctx, 2*ShortTimeout)
	defer cancel()

	if service.Service.Spec.ClusterIP == corev1.ClusterIPNone {
		// If the cluster is headless there is nothing to wait for here
		return nil
	}

	for {
		stdout, err := client.K8sClient.ExecInPod(ctx,
			client.Namespace(), client.NameWithoutNamespace(), "",
			[]string{"nslookup", service.Service.Name}) // BusyBox nslookup doesn't support any arguments.

		// Lookup successful.
		if err == nil {
			svcIP := service.Service.Spec.ClusterIP
			if svcIP == "" {
				return nil
			}

			nslookupStr := strings.ReplaceAll(stdout.String(), "\r\n", "\n")
			if strings.Contains(nslookupStr, "Address: "+svcIP+"\n") {
				return nil
			}
			err = fmt.Errorf("Service IP %q not found in nslookup output %q", svcIP, nslookupStr)
		}

		log.Debugf("[%s] Error checking service %s: %s: %s",
			client.K8sClient.ClusterName(), service.Name(), err, stdout.String())

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for service %s (last error: %w)", service.Name(), err)
		}
	}
}

// WaitForServiceEndpoints waits until the expected number of service backends
// are reported by the given agent.
func WaitForServiceEndpoints(ctx context.Context, log Logger, agent Pod, service Service, backends uint, families []features.IPFamily) error {
	log.Logf("⌛ [%s] Waiting for Service %s to be synchronized by Cilium pod %s",
		agent.K8sClient.ClusterName(), service.Name(), agent.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	if service.Service.Spec.ClusterIP == corev1.ClusterIPNone {
		// If the cluster is headless there is nothing to wait for here
		return nil
	}

	for {
		err := checkServiceEndpoints(ctx, agent, service, backends, families)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Service %s not yet correctly synchronized by Cilium pod %s: %s",
			agent.K8sClient.ClusterName(), service.Name(), agent.Name(), err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for service %s to appear in Cilium pod %s (last error: %w)",
				service.Name(), agent.Name(), err)
		}
	}
}

func checkServiceEndpoints(ctx context.Context, agent Pod, service Service, backends uint, families []features.IPFamily) error {
	buffer, err := agent.K8sClient.ExecInPod(ctx, agent.Namespace(), agent.NameWithoutNamespace(),
		defaults.AgentContainerName, []string{"cilium", "service", "list", "--output=json"})
	if err != nil {
		return fmt.Errorf("failed to query service list: %w", err)
	}

	var services []*models.Service
	if err := json.Unmarshal(buffer.Bytes(), &services); err != nil {
		return fmt.Errorf("failed to unmarshal service list output: %w", err)
	}

	type l3n4 struct {
		addr string
		port uint16
	}

	found := make(map[l3n4]uint)
	for _, svc := range services {
		found[l3n4{
			addr: svc.Spec.FrontendAddress.IP,
			port: svc.Spec.FrontendAddress.Port,
		}] = uint(len(svc.Spec.BackendAddresses))
	}

	for _, ip := range service.Service.Spec.ClusterIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("failed to parse ClusterIP %q: %w", ip, err)
		}

		// Skip the check for a given address if the corresponding IP family is not
		// enabled in Cilium, as the backends will never be populated.
		if addr.Is4() && !slices.Contains(families, features.IPFamilyV4) || addr.Is6() && !slices.Contains(families, features.IPFamilyV6) {
			continue
		}

		for _, port := range service.Service.Spec.Ports {
			if found[l3n4{addr: ip, port: uint16(port.Port)}] < backends {
				return errors.New("service not yet synchronized")
			}
		}
	}

	return nil
}

// WaitForNodePorts waits until all the nodeports in a service are available on a given node.
func WaitForNodePorts(ctx context.Context, log Logger, client Pod, nodeIP string, service Service) error {
	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	for _, port := range service.Service.Spec.Ports {
		nodePort := port.NodePort
		if nodePort == 0 {
			continue
		}

		log.Logf("⌛ [%s] Waiting for NodePort %s:%d (%s) to become ready...",
			client.K8sClient.ClusterName(), nodeIP, nodePort, service.Name())
		for {
			stdout, err := client.K8sClient.ExecInPod(ctx,
				client.Namespace(), client.NameWithoutNamespace(), "",
				[]string{"nc", "-w", "3", "-z", nodeIP, strconv.Itoa(int(nodePort))})
			if err == nil {
				break
			}

			log.Debugf("[%s] Error checking NodePort %s:%d (%s): %s: %s",
				client.K8sClient.ClusterName(), nodeIP, nodePort, service.Name(), err, stdout.String())

			select {
			case <-time.After(PollInterval):
			case <-ctx.Done():
				return fmt.Errorf("timeout reached waiting for NodePort %s:%d (%s) (last error: %w)",
					nodeIP, nodePort, service.Name(), err)
			}
		}
	}

	return nil
}

// WaitForIPCache waits until all the specified pods are present in the IPCache of the given agent.
func WaitForIPCache(ctx context.Context, log Logger, agent Pod, pods []Pod) error {
	log.Logf("⌛ [%s] Waiting for Cilium pod %s to have all the pod IPs in eBPF IPCache...",
		agent.K8sClient.ClusterName(), agent.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	for {
		err := validateIPCache(ctx, agent, pods)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Error checking pod IPs in IPCache: %s", agent.K8sClient.ClusterName(), err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for pod IPs to be in IPCache of Cilium pod %s (last error: %w)",
				agent.Name(), err)
		}
	}
}

// BPFEgressGatewayPolicyEntry represents an entry in the BPF egress gateway policy map
type BPFEgressGatewayPolicyEntry struct {
	SourceIP  string `json:"sourceIP"`
	DestCIDR  string `json:"destCIDR"`
	EgressIP  string `json:"egressIP"`
	GatewayIP string `json:"gatewayIP"`
}

// matches is an helper used to compare the receiver bpfEgressGatewayPolicyEntry with another entry
func (e *BPFEgressGatewayPolicyEntry) matches(t BPFEgressGatewayPolicyEntry) bool {
	return t.SourceIP == e.SourceIP &&
		t.DestCIDR == e.DestCIDR &&
		t.EgressIP == e.EgressIP &&
		t.GatewayIP == e.GatewayIP
}

// WaitForEgressGatewayBpfPolicyEntries waits for the egress gateway policy maps on each node to WaitForEgressGatewayBpfPolicyEntries
// with the entries returned by the targetEntriesCallback
func WaitForEgressGatewayBpfPolicyEntries(ctx context.Context, ciliumPods map[string]Pod,
	targetEntriesCallback func(ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error),
	excludeEntries func(ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error),
) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBpfPolicyEntries := func() error {
		for _, ciliumPod := range ciliumPods {
			targetEntries, err := targetEntriesCallback(ciliumPod)
			if err != nil {
				return fmt.Errorf("failed to get target entries: %w", err)
			}

			cmd := strings.Split("cilium bpf egress list -o json", " ")
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				return fmt.Errorf("failed to run cilium bpf egress list command: %w", err)
			}

			var entries []BPFEgressGatewayPolicyEntry
			json.Unmarshal(stdout.Bytes(), &entries)

			excludes, err := excludeEntries(ciliumPod)
			if err != nil {
				return fmt.Errorf("failed to get exclude entries: %w", err)
			}
			for _, exclude := range excludes {
				entries = slices.DeleteFunc(entries, func(entry BPFEgressGatewayPolicyEntry) bool {
					return entry.matches(exclude)
				})
			}

			for _, targetEntry := range targetEntries {
				if !slices.ContainsFunc(entries, targetEntry.matches) {
					return fmt.Errorf("could not find egress gateway policy entry matching %+v", targetEntry)
				}
			}

			for _, entry := range entries {
				if !slices.ContainsFunc(targetEntries, entry.matches) {
					return fmt.Errorf("untracked entry %+v in the egress gateway policy maps", entry)
				}
			}
		}

		return nil
	}

	for {
		if err := ensureBpfPolicyEntries(); err != nil {
			if err := w.Retry(err); err != nil {
				return fmt.Errorf("failed to ensure egress gateway policy maps are properly populated: %w", err)
			}

			continue
		}

		return nil
	}
}

func validateIPCache(ctx context.Context, agent Pod, pods []Pod) error {
	stdout, err := agent.K8sClient.ExecInPod(ctx, agent.Namespace(), agent.NameWithoutNamespace(),
		defaults.AgentContainerName, []string{"cilium", "bpf", "ipcache", "list", "-o", "json"})
	if err != nil {
		return fmt.Errorf("failed to list ipcache bpf map: %w", err)
	}

	var ic ipCache
	if err := json.Unmarshal(stdout.Bytes(), &ic); err != nil {
		return fmt.Errorf("failed to unmarshal Cilium ipcache stdout json: %w", err)
	}

	for _, pod := range pods {
		if _, err := ic.findPodID(pod); err != nil {
			return fmt.Errorf("couldn't find pod %s in ipcache: %w", pod.Name(), err)
		}
	}

	return nil
}

// DeleteK8sResourceWithWait deletes the provided k8s resource and waits until it is deleted.
func DeleteK8sResourceWithWait[T any](ctx context.Context, t *Test, k8sClient k8s.ResourceClient[T], resourceName string) {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: ShortTimeout})
	defer w.Cancel()

	err := k8sClient.Delete(ctx, resourceName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		t.Fatalf("Failed to delete k8s resorce %s: %v", resourceName, err)
	}
	for {
		_, err = k8sClient.Get(ctx, resourceName, metav1.GetOptions{})
		if err != nil && k8serrors.IsNotFound(err) {
			return // got expected not found
		}
		if err = w.Retry(err); err != nil {
			t.Fatalf("Failed to ensure k8s resorce %s is deleted: %v", resourceName, err)
		}
	}
}
