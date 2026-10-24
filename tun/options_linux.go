/* SPDX-License-Identifier: MIT */

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// Options configures a Linux TUN before it starts processing packets.
// Zero options preserve the existing offload behaviour.
type Options struct {
	// DisableSegmentationOffloads disables TUN segmentation offloads and GRO.
	// Framed descriptors retain checksum offload, completed during reads.
	// Virtio framing, when present, is retained for interface status detection.
	DisableSegmentationOffloads bool
}

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN(name string, mtu int) (Device, error) {
	return CreateTUNWithOptions(name, mtu, Options{})
}

// CreateTUNFromFile creates a Device from an os.File with the provided MTU.
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	return CreateTUNFromFileWithOptions(file, mtu, Options{})
}

// CreateUnmonitoredTUNFromFD creates a Device from the provided file descriptor.
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	return CreateUnmonitoredTUNFromFDWithOptions(fd, Options{})
}

// configureOffloads preserves normal negotiation and allocations. Compact mode
// retains checksum offload and disables segmentation offloads. The callback
// permits testing ioctl failures without a kernel TUN.
func (tun *NativeTun) configureOffloads(flags uint16, options Options, setOffloads func(int) error) error {
	tun.vnetHdr = flags&unix.IFF_VNET_HDR != 0
	tun.noSegmentation = options.DisableSegmentationOffloads
	tun.batchSize = 1
	if tun.noSegmentation {
		if tun.vnetHdr {
			if err := setOffloads(unix.TUN_F_CSUM); err != nil {
				return fmt.Errorf("configure checksum-only TUN offload: %w", err)
			}
		}
		return nil
	}
	// Keep normal-mode allocation behaviour, including unframed descriptors.
	tun.tcpGROTable, tun.udpGROTable = newTCPGROTable(), newUDPGROTable()
	tun.toWrite = make([]int, 0, conn.IdealBatchSize)
	if tun.vnetHdr {
		if err := setOffloads(tunTCPOffloads); err != nil {
			return err
		}
		tun.batchSize = conn.IdealBatchSize
		// UDP offloads are optional on kernels older than Linux 6.2.
		tun.udpGSO = setOffloads(tunTCPOffloads|tunUDPOffloads) == nil
	}
	return nil
}

// readWithoutSegmentation reads one complete packet before checking the caller's
// capacity, so short buffers cannot silently truncate it. The caller holds readOpMu.
func (tun *NativeTun) readWithoutSegmentation(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		n, err := tun.tunFile.Read(tun.readBuff[:])
		if errors.Is(err, syscall.EBADFD) {
			err = os.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		return readPlain(tun.readBuff[:n], tun.vnetHdr, bufs[0], sizes, offset)
	}
}

// readPlain completes a partial checksum and copies one fully segmented packet.
// Compact framed descriptors use a ten-byte, explicitly little-endian header.
func readPlain(in []byte, vnetHdr bool, out []byte, sizes []int, offset int) (int, error) {
	var needsChecksum bool
	var start, checksumOffset int
	if vnetHdr {
		if len(in) < virtioNetHdrLen {
			return 0, errors.New("short TUN virtio header")
		}
		if in[1] != unix.VIRTIO_NET_HDR_GSO_NONE {
			return 0, errors.New("unexpected TUN segmentation request")
		}
		needsChecksum = in[0]&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0
		start = int(binary.LittleEndian.Uint16(in[6:8]))
		checksumOffset = int(binary.LittleEndian.Uint16(in[8:10]))
		in = in[virtioNetHdrLen:]
	}
	if len(in) == 0 {
		return 0, errors.New("empty TUN packet")
	}
	if len(sizes) == 0 || offset < 0 || offset > len(out) || len(in) > len(out)-offset {
		return 0, io.ErrShortBuffer
	}
	if needsChecksum {
		// The shared helper indexes with uint16. Bound the sum before conversion,
		// including inputs larger than the native read buffer used by this caller.
		if start+checksumOffset > 65534 || start+checksumOffset+2 > len(in) {
			return 0, errors.New("invalid TUN checksum bounds")
		}
		if err := gsoNoneChecksum(in, uint16(start), uint16(checksumOffset)); err != nil {
			return 0, err
		}
		// Both zero representations have the same checksum sum. Use all ones
		// so UDP does not interpret a computed zero as a missing checksum.
		at := start + checksumOffset
		if binary.BigEndian.Uint16(in[at:]) == 0 {
			binary.BigEndian.PutUint16(in[at:], 0xffff)
		}
	}
	sizes[0] = copy(out[offset:], in)
	return 1, nil
}

// configureCompactFraming validates the framing and selects a portable byte order.
// The callbacks allow failure testing without a privileged TUN descriptor.
func configureCompactFraming(getHeaderSize func() (int, error), setLittleEndian func() error) error {
	size, err := getHeaderSize()
	if err != nil {
		return fmt.Errorf("read TUN virtio header size: %w", err)
	}
	if size != virtioNetHdrLen {
		return fmt.Errorf("unsupported TUN virtio header size: %d", size)
	}
	if err := setLittleEndian(); err != nil {
		return fmt.Errorf("set TUN virtio little-endian framing: %w", err)
	}
	return nil
}

// writePlain preserves the native byte-count result and writes every packet
// separately. No GRO table or batch index storage is needed.
func (tun *NativeTun) writePlain(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) || (tun.vnetHdr && offset < virtioNetHdrLen) {
			return 0, io.ErrShortBuffer
		}
	}
	total := 0
	var errs error
	for _, buf := range bufs {
		start := offset
		if tun.vnetHdr {
			start -= virtioNetHdrLen
			clear(buf[start:offset])
		}
		n, err := tun.tunFile.Write(buf[start:])
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}
