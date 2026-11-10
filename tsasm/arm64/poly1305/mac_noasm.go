//go:build !arm64 || !gc || purego

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in the repository-root LICENSE file.
package poly1305

type mac struct{ macGeneric }
