// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"fmt"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
)

const (
	// RecorderCaptureLen is the amount of data in the RecorderCapture message
	RecorderCaptureLen = 24
)

// RecorderCapture is the message format of a pcap capture in the bpf ring buffer
type RecorderCapture struct {
	DefaultSrcDstGetter
	DefaultDecoder

	Type     uint8
	SubType  uint8
	RuleID   uint16
	Reserved uint32
	TimeBoot uint64
	CapLen   uint32
	Len      uint32
	// data
}

// DumpInfo prints a summary of the recorder notify messages.
func (n *RecorderCapture) DumpInfo(buf *bufio.Writer, data []byte, numeric bool, linkMonitor getters.LinkGetter) {
	dir := "egress"
	if n.SubType == 1 {
		dir = "ingress"
	}
	fmt.Fprintf(buf, "Recorder capture: dir:%s rule:%d ts:%d caplen:%d len:%d\n",
		dir, int(n.RuleID), int(n.TimeBoot), int(n.CapLen), int(n.Len))
	Dissect(buf, true, data[RecorderCaptureLen:])
	fmt.Fprintf(buf, "----\n")
}

func (n *RecorderCapture) DumpJSON(buf *bufio.Writer, data []byte, _ int, linkMonitor getters.LinkGetter) {
	// We don't have a JSON representation yet.
	// We use DumpInfo but probably it would be better to put in place a proper JSON representation
	// Note we use `false` for numeric since we don't have the argument here.
	n.DumpInfo(buf, data, false, linkMonitor)
}

func (n *RecorderCapture) DumpVerbose(buf *bufio.Writer, data []byte, _ int, numeric bool, linkMonitor getters.LinkGetter, _ bool) {
	// We don't have a different verbose format so we just use the Info format
	n.DumpInfo(buf, data, numeric, linkMonitor)
}
