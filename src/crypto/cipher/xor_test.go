// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

func TestXOR(t *testing.T) {
	for j := 1; j <= 1024; j++ {
		if testing.Short() && j > 16 {
			break
		}
		for alignP := 0; alignP < 2; alignP++ {
			for alignQ := 0; alignQ < 2; alignQ++ {
				for alignD := 0; alignD < 2; alignD++ {
					p := make([]byte, j)[alignP:]
					q := make([]byte, j)[alignQ:]
					d1 := make([]byte, j+alignD)[alignD:]
					d2 := make([]byte, j+alignD)[alignD:]
					if _, err := io.ReadFull(rand.Reader, p); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(rand.Reader, q); err != nil {
						t.Fatal(err)
					}
					cipher.XorBytes(d1, p, q)
					n := min(p, q)
					for i := 0; i < n; i++ {
						d2[i] = p[i] ^ q[i]
					}
					if !bytes.Equal(d1, d2) {
						t.Logf("p: %#v", p)
						t.Logf("q: %#v", q)
						t.Logf("expect: %#v", d2)
						t.Logf("result: %#v", d1)
						t.Fatal("not equal")
					}
				}
			}
		}
	}
}

func min(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	return n
}

func BenchmarkXORBytes(b *testing.B) {
	dst := make([]byte, 1<<15)
	data0 := make([]byte, 1<<15)
	data1 := make([]byte, 1<<15)
	sizes := []int64{1 << 3, 1 << 7, 1 << 11, 1 << 15}

	var fns = []struct{
		name string
		fn func(dst, a, b []byte) int
	}{
		{
			name: "default",
			fn: cipher.XorBytes,
		},
		{
			name: "safe",
			fn:   safeXORBytes,
		},
		{
			name: "fastSafe",
			fn: fastSafeXORBytes,
		},
	}

	for _, size := range sizes {
		for _, fn := range fns {
			b.Run(fn.name, func(b *testing.B) {
				b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
					s0 := data0[:size]
					s1 := data1[:size]
					b.SetBytes(size)
					for i := 0; i < b.N; i++ {
						fn.fn(dst, s0, s1)
					}
				})
			})
		}
	}
}

func safeXORBytes(dst, a, b []byte) int {
	if len(a) > len(b) {
		a = a[:len(b)]
	}

	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b[i]
	}
	return len(a)
}

// Unrolled generic version for performance.
// See https://github.com/golang/go/issues/35381
func fastSafeXORBytes(dst, a, b []byte) int {
	if len(a) > len(b) {
		a = a[:len(b)]
	}
	n := len(a)

	// At some point in the future we can clean these unrolled loops up.
	// See https://github.com/golang/go/issues/31586#issuecomment-487436401

	for len(a) >= 128 {
		va := binary.LittleEndian.Uint64(a)
		vb := binary.LittleEndian.Uint64(b)
		binary.LittleEndian.PutUint64(dst, va^vb)

		va = binary.LittleEndian.Uint64(a[8:16])
		vb = binary.LittleEndian.Uint64(b[8:16])
		binary.LittleEndian.PutUint64(dst[8:16], va^vb)

		va = binary.LittleEndian.Uint64(a[16:24])
		vb = binary.LittleEndian.Uint64(b[16:24])
		binary.LittleEndian.PutUint64(dst[16:24], va^vb)

		va = binary.LittleEndian.Uint64(a[24:32])
		vb = binary.LittleEndian.Uint64(b[24:32])
		binary.LittleEndian.PutUint64(dst[24:32], va^vb)

		va = binary.LittleEndian.Uint64(a[32:40])
		vb = binary.LittleEndian.Uint64(b[32:40])
		binary.LittleEndian.PutUint64(dst[32:40], va^vb)

		va = binary.LittleEndian.Uint64(a[40:48])
		vb = binary.LittleEndian.Uint64(b[40:48])
		binary.LittleEndian.PutUint64(dst[40:48], va^vb)

		va = binary.LittleEndian.Uint64(a[56:64])
		vb = binary.LittleEndian.Uint64(b[56:64])
		binary.LittleEndian.PutUint64(dst[56:64], va^vb)

		va = binary.LittleEndian.Uint64(a[64:72])
		vb = binary.LittleEndian.Uint64(b[64:72])
		binary.LittleEndian.PutUint64(dst[64:72], va^vb)

		va = binary.LittleEndian.Uint64(a[72:80])
		vb = binary.LittleEndian.Uint64(b[72:80])
		binary.LittleEndian.PutUint64(dst[72:80], va^vb)

		va = binary.LittleEndian.Uint64(a[80:88])
		vb = binary.LittleEndian.Uint64(b[80:88])
		binary.LittleEndian.PutUint64(dst[80:88], va^vb)

		va = binary.LittleEndian.Uint64(a[88:96])
		vb = binary.LittleEndian.Uint64(b[88:96])
		binary.LittleEndian.PutUint64(dst[88:96], va^vb)

		va = binary.LittleEndian.Uint64(a[96:104])
		vb = binary.LittleEndian.Uint64(b[96:104])
		binary.LittleEndian.PutUint64(dst[96:104], va^vb)

		va = binary.LittleEndian.Uint64(a[104:112])
		vb = binary.LittleEndian.Uint64(b[104:112])
		binary.LittleEndian.PutUint64(dst[104:112], va^vb)

		va = binary.LittleEndian.Uint64(a[112:120])
		vb = binary.LittleEndian.Uint64(b[112:120])
		binary.LittleEndian.PutUint64(dst[112:120], va^vb)

		va = binary.LittleEndian.Uint64(a[120:128])
		vb = binary.LittleEndian.Uint64(b[120:128])
		binary.LittleEndian.PutUint64(dst[120:128], va^vb)

		a = a[128:]
		b = b[128:]
		dst = dst[128:]
	}

	for len(a) >= 64 {
		va := binary.LittleEndian.Uint64(a)
		vb := binary.LittleEndian.Uint64(b)
		binary.LittleEndian.PutUint64(dst, va^vb)

		va = binary.LittleEndian.Uint64(a[8:16])
		vb = binary.LittleEndian.Uint64(b[8:16])
		binary.LittleEndian.PutUint64(dst[8:16], va^vb)

		va = binary.LittleEndian.Uint64(a[16:24])
		vb = binary.LittleEndian.Uint64(b[16:24])
		binary.LittleEndian.PutUint64(dst[16:24], va^vb)

		va = binary.LittleEndian.Uint64(a[24:32])
		vb = binary.LittleEndian.Uint64(b[24:32])
		binary.LittleEndian.PutUint64(dst[24:32], va^vb)

		va = binary.LittleEndian.Uint64(a[32:40])
		vb = binary.LittleEndian.Uint64(b[32:40])
		binary.LittleEndian.PutUint64(dst[32:40], va^vb)

		va = binary.LittleEndian.Uint64(a[40:48])
		vb = binary.LittleEndian.Uint64(b[40:48])
		binary.LittleEndian.PutUint64(dst[40:48], va^vb)

		va = binary.LittleEndian.Uint64(a[56:64])
		vb = binary.LittleEndian.Uint64(b[56:64])
		binary.LittleEndian.PutUint64(dst[56:64], va^vb)

		a = a[64:]
		b = b[64:]
		dst = dst[64:]
	}

	for len(a) >= 32 {
		va := binary.LittleEndian.Uint64(a)
		vb := binary.LittleEndian.Uint64(b)
		binary.LittleEndian.PutUint64(dst, va^vb)

		va = binary.LittleEndian.Uint64(a[8:16])
		vb = binary.LittleEndian.Uint64(b[8:16])
		binary.LittleEndian.PutUint64(dst[8:16], va^vb)

		va = binary.LittleEndian.Uint64(a[16:24])
		vb = binary.LittleEndian.Uint64(b[16:24])
		binary.LittleEndian.PutUint64(dst[16:24], va^vb)

		va = binary.LittleEndian.Uint64(a[24:32])
		vb = binary.LittleEndian.Uint64(b[24:32])
		binary.LittleEndian.PutUint64(dst[24:32], va^vb)

		a = a[32:]
		b = b[32:]
		dst = dst[32:]
	}

	for len(a) >= 16 {
		va := binary.LittleEndian.Uint64(a)
		vb := binary.LittleEndian.Uint64(b)
		binary.LittleEndian.PutUint64(dst, va^vb)

		va = binary.LittleEndian.Uint64(a[8:16])
		vb = binary.LittleEndian.Uint64(b[8:16])
		binary.LittleEndian.PutUint64(dst[8:16], va^vb)

		a = a[16:]
		b = b[16:]
		dst = dst[16:]
	}

	for len(a) >= 8 {
		va := binary.LittleEndian.Uint64(a)
		vb := binary.LittleEndian.Uint64(b)
		binary.LittleEndian.PutUint64(dst, va^vb)

		a = a[8:]
		b = b[8:]
		dst = dst[8:]
	}

	for len(a) >= 4 {
		va := binary.LittleEndian.Uint32(a)
		vb := binary.LittleEndian.Uint32(b)
		binary.LittleEndian.PutUint32(dst, va^vb)

		a = a[4:]
		b = b[4:]
		dst = dst[4:]
	}

	// xor remaining bytes.
	for i := range a {
		dst[i] = a[i] ^ b[i]
	}

	return n
}
