// SPDX-License-Identifier: MIT

package tun

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxReadRecords bounds work per call without delaying a partially full batch.
const maxReadRecords = 4

// readQueuedRecords drains at most four immediately available records. The
// first read may block; subsequent reads never wait for more traffic. One raw
// record can remain in readBuff until the next call when its GSO segments do
// not fit. The caller holds readOpMu, so readBuff has exactly one owner.
func (tun *NativeTun) readQueuedRecords(bufs [][]byte, sizes []int, offset int) (int, error) {
	count := 0
	for records := 0; records < maxReadRecords && count < len(bufs); records++ {
		n := tun.pendingRead
		tun.pendingRead = 0
		if n == 0 {
			var err error
			if count == 0 {
				n, err = tun.tunFile.Read(tun.readBuff[:])
			} else {
				n, err = tun.readRecordNow()
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					return count, nil
				}
			}
			if errors.Is(err, syscall.EBADFD) {
				err = os.ErrClosed
			}
			if err != nil {
				return count, err
			}
		}
		added, err := handleVirtioRead(tun.readBuff[:n], bufs[count:], sizes[count:], offset)
		if errors.Is(err, ErrTooManySegments) && count > 0 {
			tun.pendingRead = n
			return count, nil
		}
		count += added
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

// readRecordNow uses the runtime-owned descriptor without changing its flags.
// Returning true on EAGAIN deliberately prevents RawConn from waiting.
func (tun *NativeTun) readRecordNow() (n int, err error) {
	raw, err := tun.tunFile.SyscallConn()
	if err != nil {
		return 0, err
	}
	callErr := raw.Read(func(fd uintptr) bool {
		for {
			n, err = unix.Read(int(fd), tun.readBuff[:])
			if err != unix.EINTR {
				return true
			}
		}
	})
	if callErr != nil {
		return n, callErr
	}
	return n, err
}
