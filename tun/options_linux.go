/* SPDX-License-Identifier: MIT */

package tun

import (
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
	// DisableOffloads disables TUN checksum and segmentation offloads and GRO.
	// Virtio framing, when present, is retained for interface status detection.
	DisableOffloads bool
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
// retains descriptor framing but explicitly disables checksum and segmentation
// offloads. The callback permits testing ioctl failures without a kernel TUN.
func (tun *NativeTun) configureOffloads(flags uint16, options Options, setOffloads func(int) error) error {
	tun.vnetHdr = flags&unix.IFF_VNET_HDR != 0
	tun.disableOffloads = options.DisableOffloads
	tun.batchSize = 1
	if tun.disableOffloads {
		if tun.vnetHdr {
			if err := setOffloads(0); err != nil {
				return fmt.Errorf("disable TUN offloads: %w", err)
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

// readWithoutOffloads reads one complete packet before checking the caller's
// capacity, so short buffers cannot silently truncate it. The caller holds readOpMu.
func (tun *NativeTun) readWithoutOffloads(bufs [][]byte, sizes []int, offset int) (int, error) {
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

// readPlain copies one complete packet after validating any virtio framing.
// Receiving offload requests is an error when the descriptor was configured to
// deliver fully segmented packets with completed checksums.
func readPlain(in []byte, vnetHdr bool, out []byte, sizes []int, offset int) (int, error) {
	if vnetHdr {
		var hdr virtioNetHdr
		if err := hdr.decode(in); err != nil {
			return 0, err
		}
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_NONE || hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			return 0, errors.New("unexpected TUN offload request with offloads disabled")
		}
		in = in[virtioNetHdrLen:]
	}
	if len(in) == 0 {
		return 0, errors.New("empty TUN packet")
	}
	if len(sizes) == 0 || offset < 0 || offset > len(out) || len(in) > len(out)-offset {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(out[offset:], in)
	return 1, nil
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
