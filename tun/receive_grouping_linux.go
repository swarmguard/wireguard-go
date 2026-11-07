// SPDX-License-Identifier: MIT
package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/packetbudget"
)

const (
	// receiveGroupPackets bounds workspace and bookkeeping for each TUN.
	receiveGroupPackets = 12
	// receiveGroupBytes bounds each aggregate; larger groups are split.
	receiveGroupBytes = 16 * 1024
)

// receiveGrouping owns one fixed workspace shared by synchronous TUN writers.
// Packet storage is charged to the data budget and is never held per peer.
type receiveGrouping struct {
	budget  *packetbudget.Budget
	owners  [receiveGroupPackets][]byte
	bufs    [receiveGroupPackets][]byte
	indexes []int
	tcp     *tcpGROTable
	udp     *udpGROTable
}

// initReceiveGrouping reserves the complete workspace before traffic starts.
func (tun *NativeTun) initReceiveGrouping(budget *packetbudget.Budget) error {
	g := &receiveGrouping{budget: budget}
	tun.receiveGrouping = g
	for i := range g.owners {
		g.owners[i] = budget.Get(receiveGroupBytes, false)
		if g.owners[i] == nil {
			tun.closeReceiveGrouping()
			return packetbudget.ErrExhausted
		}
	}
	g.indexes = make([]int, 0, receiveGroupPackets)
	g.tcp = newTCPGROTableSized(receiveGroupPackets)
	g.udp = newUDPGROTableSized(receiveGroupPackets)
	return nil
}

// closeReceiveGrouping releases original owners, never swapped GRO slices.
// The caller excludes concurrent writes, or has not published the device yet.
func (tun *NativeTun) closeReceiveGrouping() {
	g := tun.receiveGrouping
	if g == nil {
		return
	}
	for i, b := range g.owners {
		if b != nil {
			g.budget.Put(b)
			g.owners[i] = nil
		}
	}
	tun.receiveGrouping = nil
}

// writeGrouped uses only packets already supplied in this synchronous call.
// The existing write mutex protects all buffers and GRO bookkeeping.
func (tun *NativeTun) writeGrouped(bufs [][]byte, offset int) (int, error) {
	return tun.writeGroupedTo(bufs, offset, tun.tunFile.Write)
}

// writeGroupedTo permits failure and byte-count testing without a kernel TUN.
func (tun *NativeTun) writeGroupedTo(bufs [][]byte, offset int, write func([]byte) (int, error)) (int, error) {
	for _, b := range bufs {
		if offset < virtioNetHdrLen || offset > len(b) {
			return 0, io.ErrShortBuffer
		}
	}
	g := tun.receiveGrouping
	total := 0
	var errs error
	for len(bufs) > 0 {
		count := min(len(bufs), receiveGroupPackets)
		batch := bufs[:count]
		bufs = bufs[count:]

		// Unusual oversized/empty input keeps the ordinary packet write path.
		ordinary := false
		for _, b := range batch {
			if len(b) > receiveGroupBytes || len(b) == offset {
				ordinary = true
			}
		}
		if ordinary {
			for _, b := range batch {
				clear(b[offset-virtioNetHdrLen : offset])
				n, err := write(b[offset-virtioNetHdrLen:])
				if errors.Is(err, syscall.EBADFD) {
					return total, os.ErrClosed
				}
				if err != nil {
					errs = errors.Join(errs, err)
				} else {
					total += n
				}
			}
			continue
		}
		for i, b := range batch {
			g.bufs[i] = g.owners[i][:len(b)]
			copy(g.bufs[i], b)
		}
		g.indexes = g.indexes[:0]
		err := handleGRO(g.bufs[:count], offset, g.tcp, g.udp, false, &g.indexes)
		if err == nil {
			for _, i := range g.indexes {
				frame := g.bufs[i][offset-virtioNetHdrLen:]
				// The shared GRO helper encodes native-endian headers, while
				// the non-segmenting TUN negotiates little-endian framing.
				if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
					receiveGroupHeaderLittleEndian(frame, binary.NativeEndian)
				}
				n, writeErr := write(frame)
				if errors.Is(writeErr, syscall.EBADFD) {
					err = os.ErrClosed
					break
				}
				if writeErr != nil {
					errs = errors.Join(errs, writeErr)
				} else {
					total += n
				}
			}
		}

		// GRO can swap slice headers; original owners stay separate and unchanged.
		g.tcp.reset()
		g.udp.reset()
		clear(g.bufs[:])
		g.indexes = g.indexes[:0]
		if err != nil {
			return total, errors.Join(errs, err)
		}
	}
	return total, errs
}

// receiveGroupHeaderLittleEndian converts the shared GRO header to the byte
// order negotiated by configureCompactFraming. Packet contents are unchanged.
// The input is a validated ten-byte header produced by handleGRO.
func receiveGroupHeaderLittleEndian(frame []byte, order binary.ByteOrder) {
	for at := 2; at < virtioNetHdrLen; at += 2 {
		value := order.Uint16(frame[at : at+2])
		binary.LittleEndian.PutUint16(frame[at:at+2], value)
	}
}
