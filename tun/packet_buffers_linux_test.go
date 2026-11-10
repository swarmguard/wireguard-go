/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestSmallNativeBufferCapabilities requires explicit segmentation disablement.
func TestSmallNativeBufferCapabilities(t *testing.T) {
	for _, plain := range []bool{false, true} {
		native := &NativeTun{noSegmentation: plain, batchSize: 1}
		caps := PacketBuffers(native)
		if caps.ReadConsumesWholePacket != plain || caps.WriteUsesPacketLength != plain {
			t.Fatal("batch size inferred capabilities")
		}
	}
}

// TestSmallNativeRead consumes an oversized frame before a subsequent valid one.
func TestSmallNativeRead(t *testing.T) {
	for _, framed := range []bool{false, true} {
		dev, peer := socketTun(t, true, framed)
		prefix := 0
		if framed {
			prefix = virtioNetHdrLen
		}
		oversized := make([]byte, prefix+4096)
		if _, err := peer.Write(oversized); err != nil {
			t.Fatal(err)
		}
		bufs := [][]byte{make([]byte, 2032)}
		sizes := []int{-1}
		if n, err := dev.Read(bufs, sizes, 16); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("oversized read: %d %v", n, err)
		}
		payload := bytes.Repeat([]byte{0x42}, 1280)
		if _, err := peer.Write(append(make([]byte, prefix), payload...)); err != nil {
			t.Fatal(err)
		}
		if n, err := dev.Read(bufs, sizes, 16); n != 1 || err != nil || !bytes.Equal(bufs[0][16:16+sizes[0]], payload) {
			t.Fatalf("recovery: %d %v", n, err)
		}
	}
}
