// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package format

import (
	"bufio"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

// Verbosity levels for formatting output.
type Verbosity uint8

const (
	msgSeparator = "------------------------------------------------------------------------------"

	// INFO is the level of verbosity in which summaries of Drop and Capture
	// messages are printed out when the monitor is invoked
	INFO Verbosity = iota + 1
	// DEBUG is the level of verbosity in which more information about packets
	// is printed than in INFO mode. Debug, Drop, and Capture messages are printed.
	DEBUG
	// VERBOSE is the level of verbosity in which the most information possible
	// about packets is printed out. Currently is not utilized.
	VERBOSE
	// JSON is the level of verbosity in which event information is printed out in json format
	JSON
)

// MonitorFormatter filters and formats monitor messages from a buffer.
type MonitorFormatter struct {
	EventTypes monitorAPI.MessageTypeFilter
	FromSource Uint16Flags
	ToDst      Uint16Flags
	Related    Uint16Flags
	Hex        bool
	JSONOutput bool
	Verbosity  Verbosity
	Numeric    bool

	linkMonitor getters.LinkGetter
	buf         *bufio.Writer
}

// NewMonitorFormatter returns a new formatter with default configuration.
func NewMonitorFormatter(verbosity Verbosity, linkMonitor getters.LinkGetter, w io.Writer) *MonitorFormatter {
	return &MonitorFormatter{
		Hex:         false,
		EventTypes:  monitorAPI.MessageTypeFilter{},
		FromSource:  Uint16Flags{},
		ToDst:       Uint16Flags{},
		Related:     Uint16Flags{},
		JSONOutput:  false,
		Verbosity:   verbosity,
		Numeric:     bool(monitor.DisplayLabel),
		linkMonitor: linkMonitor,
		buf:         bufio.NewWriter(w),
	}
}

// match checks if the event type, from endpoint and / or to endpoint match
// when they are supplied. The either part of from and to endpoint depends on
// related to, which can match on both.  If either one of them is less than or
// equal to zero, then it is assumed user did not use them.
func (m *MonitorFormatter) match(messageType int, src uint16, dst uint16) bool {
	if len(m.EventTypes) > 0 && !m.EventTypes.Contains(messageType) {
		return false
	} else if len(m.FromSource) > 0 && !m.FromSource.Has(src) {
		return false
	} else if len(m.ToDst) > 0 && !m.ToDst.Has(dst) {
		return false
	} else if len(m.Related) > 0 && !m.Related.Has(src) && !m.Related.Has(dst) {
		return false
	}

	return true
}

// FormatSample prints an event from the provided raw data slice to stdout.
//
// For most monitor event types, 'data' corresponds to the 'data' field in
// bpf.PerfEventSample. Exceptions are MessageTypeAccessLog and
// MessageTypeAgent.
func (m *MonitorFormatter) FormatSample(data []byte, cpu int) {
	defer m.buf.Flush()
	messageType := int(data[0])
	var msg monitor.MonitorEvent
	switch messageType {
	case monitorAPI.MessageTypeDrop:
		msg = &monitor.DropNotify{}
	case monitorAPI.MessageTypeDebug:
		msg = &monitor.DebugMsg{}
	case monitorAPI.MessageTypeCapture:
		msg = &monitor.DebugCapture{}
	case monitorAPI.MessageTypeTrace:
		msg = &monitor.TraceNotify{}
	case monitorAPI.MessageTypeAccessLog:
		msg = &monitor.LogRecordNotify{}
	case monitorAPI.MessageTypeAgent:
		msg = &monitorAPI.AgentNotify{}
	case monitorAPI.MessageTypePolicyVerdict:
		msg = &monitor.PolicyVerdictNotify{}
	case monitorAPI.MessageTypeRecCapture:
		msg = &monitor.RecorderCapture{}
	case monitorAPI.MessageTypeTraceSock:
		msg = &monitor.TraceSockNotify{}
	default:
		// should we panic here?
		fmt.Fprint(m.buf, "CPU %02d Unknown event type: %d\n", cpu, messageType)
		return
	}

	if err := msg.Decode(data); err != nil {
		fmt.Fprint(m.buf, "cannot decode message type '%d': %v\n", messageType, err)
		return
	}

	// TraceSock is the only message type that has a DumpDebug method.
	// Instead of implementing it for all message types, we explicitly check for it here.
	if ts, ok := msg.(*monitor.TraceSockNotify); ok {
		if m.Verbosity == DEBUG {
			ts.DumpDebug(m.buf, cpu)
		}
		return
	}

	if !m.match(messageType, msg.GetSrc(), msg.GetDst()) {
		return
	}

	switch m.Verbosity {
	case INFO, DEBUG:
		msg.DumpInfo(m.buf, data, m.Numeric, m.linkMonitor)
	case JSON:
		msg.DumpJSON(m.buf, data, cpu, m.linkMonitor)
	case VERBOSE:
		fmt.Fprintln(m.buf, msgSeparator)
		msg.DumpVerbose(m.buf, data, cpu, m.Numeric, m.linkMonitor, !m.Hex)
	default:
		panic("unknown verbosity level")
	}
}

// LostEvent formats a lost event using the specified payload parameters.
func (m *MonitorFormatter) LostEvent(lost uint64, cpu int) {
	defer m.buf.Flush()
	fmt.Fprintf(m.buf, "CPU %02d: Lost %d events\n", cpu, lost)
}

// FormatEvent formats an event from the specified payload to stdout.
//
// Returns true if the event was successfully printed, false otherwise.
func (m *MonitorFormatter) FormatEvent(pl *payload.Payload) bool {
	switch pl.Type {
	case payload.EventSample:
		m.FormatSample(pl.Data, pl.CPU)
	case payload.RecordLost:
		m.LostEvent(pl.Lost, pl.CPU)
	default:
		return false
	}

	return true
}
