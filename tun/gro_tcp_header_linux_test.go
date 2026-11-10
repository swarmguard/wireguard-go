// SPDX-License-Identifier: MIT

package tun

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// timestampFixture returns a checksum-valid segment with a TCP timestamp option.
func timestampFixture(seq, tsval, tsecr uint32) []byte {
	raw := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1212, seq)
	ip := header.IPv4(raw[offset:])
	tcp := header.TCP(raw[offset+20:])
	tcp[12] = 8 << 4
	copy(tcp[20:32], []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint32(tcp[24:28], tsval)
	binary.BigEndian.PutUint32(tcp[28:32], tsecr)
	tcp.SetChecksum(0)
	pseudo := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
	tcp.SetChecksum(^tcp.CalculateChecksum(pseudo))
	return raw
}

// TestGROPreservesTimestampOptions checks the segments delivered after GRO and
// later GSO splitting retain their original per-segment TCP timestamps.
func TestGROPreservesTimestampOptions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		vals, echo [2]uint32
	}{
		{"increasing", [2]uint32{100, 101}, [2]uint32{7, 7}},
		{"stale second", [2]uint32{100, 99}, [2]uint32{7, 7}},
		{"wraparound", [2]uint32{0xffffffff, 0}, [2]uint32{7, 7}},
		{"changed echo", [2]uint32{100, 100}, [2]uint32{7, 8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bufs := [][]byte{timestampFixture(1, tc.vals[0], tc.echo[0]), timestampFixture(1201, tc.vals[1], tc.echo[1])}
			var groups []int
			if err := handleGRO(bufs, offset, newTCPGROTable(), newUDPGROTable(), false, &groups); err != nil {
				t.Fatal(err)
			}
			got := make([][2]uint32, 0, 2)
			for _, i := range groups {
				out := [][]byte{make([]byte, 65536), make([]byte, 65536)}
				sizes := make([]int, 2)
				n, err := handleVirtioRead(bufs[i], out, sizes, 0)
				if err != nil {
					t.Fatal(err)
				}
				for j := 0; j < n; j++ {
					if sizes[j] < 52 {
						t.Fatal("short segment")
					}
					got = append(got, [2]uint32{binary.BigEndian.Uint32(out[j][44:48]), binary.BigEndian.Uint32(out[j][48:52])})
				}
			}
			if len(got) != 2 {
				t.Fatalf("got %d segments", len(got))
			}
			for i := range got {
				want := [2]uint32{tc.vals[i], tc.echo[i]}
				if got[i] != want {
					t.Errorf("segment %d: got TSval/TSecr %v, want %v; groups=%d", i, got[i], want, len(groups))
				}
			}
			// RFC 7323 PAWS rejects a timestamp below TS.Recent in ordinary cases.
			if tc.name == "stale second" && int32(got[1][0]-tc.vals[0]) >= 0 {
				t.Errorf("stale second timestamp was changed into an acceptable value: %v", got[1])
			}
		})
	}
}

// TestGROPreservesTCPControlFields checks that merged packets do not hide an
// advertised-window update or differing reserved/NS bits from the receiver.
func TestGROPreservesTCPControlFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field int
		value byte
	}{
		{"advertised window", 14, 0x01},
		{"reserved or NS bit", 12, 0x81},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bufs := [][]byte{timestampFixture(1, 100, 7), timestampFixture(1201, 100, 7)}
			pkt := bufs[1][offset:]
			ip := header.IPv4(pkt)
			tcp := header.TCP(pkt[20:])
			tcp[tc.field] = tc.value
			tcp.SetChecksum(0)
			pseudo := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
			tcp.SetChecksum(^tcp.CalculateChecksum(pseudo))
			var groups []int
			if err := handleGRO(bufs, offset, newTCPGROTable(), newUDPGROTable(), false, &groups); err != nil {
				t.Fatal(err)
			}
			if len(groups) != 2 {
				t.Fatalf("different TCP %s merged into %d group(s)", tc.name, len(groups))
			}
		})
	}
}

// TestGROPreservesReorderedControlFields verifies that prepend candidates also
// keep separate records when the older segment has a different TCP window.
func TestGROPreservesReorderedControlFields(t *testing.T) {
	bufs := [][]byte{timestampFixture(1201, 100, 7), timestampFixture(1, 100, 7)}
	pkt := bufs[1][offset:]
	ip := header.IPv4(pkt)
	tcp := header.TCP(pkt[20:])
	tcp[14] = 0x01
	tcp.SetChecksum(0)
	pseudo := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
	tcp.SetChecksum(^tcp.CalculateChecksum(pseudo))
	var groups []int
	if err := handleGRO(bufs, offset, newTCPGROTable(), newUDPGROTable(), false, &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("reordered packets with different windows merged into %d group(s)", len(groups))
	}
}

// TestGROCompatibleControlFieldsStillMerge preserves the fast path for
// contiguous segments with identical control fields and timestamps.
func TestGROCompatibleControlFieldsStillMerge(t *testing.T) {
	bufs := [][]byte{timestampFixture(1, 100, 7), timestampFixture(1201, 100, 7)}
	var groups []int
	if err := handleGRO(bufs, offset, newTCPGROTable(), newUDPGROTable(), false, &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("identical compatible packets produced %d groups", len(groups))
	}
}
