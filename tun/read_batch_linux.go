/* SPDX-License-Identifier: MIT */

package tun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// readReadyPackets waits for the first frame and then drains up to the configured
// number of ready frames. It retains no packet references and adds no waiting timer.
// The caller holds readOpMu, which protects the full-frame scratch buffer.
func (tun *NativeTun) readReadyPackets(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}
	sc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return 0, tun.readyReadError(err)
	}
	count := 0
	var readErr error
	pollErr := sc.Read(func(fd uintptr) bool {
		count, readErr = readReadyBatch(tun.readBatchPackets, func(p []byte) (int, error) { return unix.Read(int(fd), p) }, tun.readBuff[:], tun.vnetHdr, bufs, sizes, offset)
		return count > 0 || readErr != nil
	})
	if errors.Is(readErr, syscall.EBADFD) {
		readErr = os.ErrClosed
	}
	if pollErr != nil {
		return count, tun.readyReadError(pollErr)
	}
	return count, readErr
}

// readReadyBatch stops when the descriptor would block. The caller decides
// whether an empty result should wait. Each frame is consumed exactly once.
func readReadyBatch(maxPackets int, read func([]byte) (int, error), scratch []byte, framed bool, bufs [][]byte, sizes []int, offset int) (int, error) {
	limit := min(len(bufs), len(sizes), maxPackets)
	if limit <= 0 || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	for i := 0; i < limit; i++ {
		if offset > len(bufs[i]) {
			return i, io.ErrShortBuffer
		}
		n, err := read(scratch)
		for errors.Is(err, unix.EINTR) {
			n, err = read(scratch)
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return i, nil
		}
		if err != nil {
			return i, err
		}
		_, err = readPlain(scratch[:n], framed, bufs[i], sizes[i:i+1], offset)
		if err != nil {
			return i, err
		}
	}
	return limit, nil
}

// readyReadError preserves File.Read's public closed-file error. RawConn may
// expose the poller's private closing error, so check the file only on failure.
func (tun *NativeTun) readyReadError(err error) error {
	if _, statErr := tun.tunFile.Stat(); errors.Is(statErr, os.ErrClosed) {
		return os.ErrClosed
	}
	return err
}

// configureReadyReader keeps the ordinary single-frame reader for a supplied
// blocking descriptor. It never changes the caller's descriptor flags.
func (tun *NativeTun) configureReadyReader(fd uintptr) error {
	if tun.readBatchPackets <= 1 {
		return nil
	}
	flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("check TUN descriptor for ready reads: %w", err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		tun.readBatchPackets = 1
	}
	tun.batchSize = tun.readBatchPackets
	return nil
}
