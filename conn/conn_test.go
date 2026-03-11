/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"testing"
)

func TestPrettyName(t *testing.T) {
	var (
		recvBorrowedFunc ReceiveBorrowedFunc = func(packets []BorrowedPacket) (n int, err error) { return }
	)

	const want = "TestPrettyName"

	t.Run("ReceiveBorrowedFunc.PrettyName", func(t *testing.T) {
		if got := recvBorrowedFunc.PrettyName(); got != want {
			t.Errorf("PrettyName() = %v, want %v", got, want)
		}
	})
}
