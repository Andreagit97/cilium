// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"bytes"
	"encoding/binary"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
)

type MonitorEvent interface {
	Decode(data []byte) error
	GetSrc() (src uint16)
	GetDst() (dst uint16)

	DumpInfo(buf *bufio.Writer, data []byte, numeric bool, linkMonitor getters.LinkGetter)
	DumpJSON(buf *bufio.Writer, data []byte, cpu int, linkMonitor getters.LinkGetter)
	DumpVerbose(buf *bufio.Writer, data []byte, cpu int, numeric bool, linkMonitor getters.LinkGetter, dissect bool)
}

type DefaultDecoder struct{}

func (d *DefaultDecoder) Decode(data []byte) error {
	return binary.Read(bytes.NewReader(data), byteorder.Native, d)
}

type DefaultSrcDstGetter struct{}

func (d *DefaultSrcDstGetter) GetSrc() (src uint16) {
	return 0
}

func (d *DefaultSrcDstGetter) GetDst() (dst uint16) {
	return 0
}

type DefaultDump struct{}

func (d *DefaultDump) DumpInfo(_ *bufio.Writer, _ []byte, _ bool, _ getters.LinkGetter) {}

func (d *DefaultDump) DumpJSON(_ *bufio.Writer, _ []byte, _ int, _ getters.LinkGetter) {}

func (d *DefaultDump) DumpVerbose(_ *bufio.Writer, _ []byte, _ int, _ bool, _ getters.LinkGetter, _ bool) {
}
