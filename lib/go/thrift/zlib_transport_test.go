/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package thrift

import (
	"bytes"
	"compress/zlib"
	"context"
	"testing"
)

func TestZlibTransport(t *testing.T) {
	trans, err := NewTZlibTransport(NewTMemoryBuffer(), zlib.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	TransportTest(t, trans, trans)
}

type DummyTransportFactory struct{}

func (p *DummyTransportFactory) GetTransport(trans TTransport) (TTransport, error) {
	return NewTMemoryBuffer(), nil
}

func TestZlibFactoryTransportWithFactory(t *testing.T) {
	factory := NewTZlibTransportFactoryWithFactory(
		zlib.BestCompression,
		&DummyTransportFactory{},
	)
	buffer := NewTMemoryBuffer()
	trans, err := factory.GetTransport(buffer)
	if err != nil {
		t.Fatal(err)
	}
	TransportTest(t, trans, trans)
}

func TestZlibFactoryTransportWithoutFactory(t *testing.T) {
	factory := NewTZlibTransportFactoryWithFactory(zlib.BestCompression, nil)
	buffer := NewTMemoryBuffer()
	trans, err := factory.GetTransport(buffer)
	if err != nil {
		t.Fatal(err)
	}
	TransportTest(t, trans, trans)
}

// zlibCompress compresses data into a fresh buffer and returns the compressed
// bytes. It flushes (rather than closes) the writer so the caller can feed the
// result to a reader without the memory buffer being wiped.
func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	writeBuf := NewTMemoryBuffer()
	writer, err := NewTZlibTransport(writeBuf, zlib.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	compressed := make([]byte, writeBuf.Len())
	copy(compressed, writeBuf.Bytes())
	return compressed
}

// TestZlibTransportDecompressionBombStopped verifies that a decompression bomb
// (a tiny compressed payload that expands enormously) is aborted with a
// SIZE_LIMIT error long before the full decompressed output is produced, rather
// than being read to completion. This is the CVE-2026-48586 fix.
func TestZlibTransportDecompressionBombStopped(t *testing.T) {
	const bombSize = 64 << 20 // 64MiB of highly compressible data
	const maxMessageSize = 64 * 1024
	const chunkSize = 4096

	compressed := zlibCompress(t, bytes.Repeat([]byte{0}, bombSize))
	if len(compressed) >= maxMessageSize {
		t.Fatalf(
			"expected the payload to be an amplification (compressed %d bytes, limit %d)",
			len(compressed), maxMessageSize,
		)
	}

	readBuf := NewTMemoryBuffer()
	readBuf.Write(compressed)
	reader, err := NewTZlibTransport(readBuf, zlib.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	reader.SetTConfiguration(&TConfiguration{MaxMessageSize: maxMessageSize})

	chunk := make([]byte, chunkSize)
	var total int64
	var readErr error
	for total < bombSize {
		n, err := reader.Read(chunk)
		total += int64(n)
		if err != nil {
			readErr = err
			break
		}
	}
	if readErr == nil {
		t.Fatalf("expected the read to be aborted, but decompressed %d bytes", total)
	}
	protoEx, ok := readErr.(TProtocolException)
	if !ok || protoEx.TypeId() != SIZE_LIMIT {
		t.Fatalf("expected SIZE_LIMIT TProtocolException, got %T: %v", readErr, readErr)
	}
	// The bomb must be stopped well before the full payload is decompressed. The
	// bound is the ratio limit applied to the compressed bytes consumed (plus
	// the reader's internal buffering), which for this payload is a small
	// fraction of the 64MiB total.
	if total >= bombSize {
		t.Errorf("decompressed %d bytes, expected the bomb to be aborted early", total)
	}
}

// TestZlibTransportLongLivedConnectionNotBroken is the regression test for the
// breaking behavior of the naive fix: it verifies that a legitimate, long-lived
// connection whose *cumulative* decompressed traffic far exceeds MaxMessageSize
// is NOT rejected, as long as its compression ratio is realistic. The upstream
// (per-connection cumulative cap) fix fails this test.
func TestZlibTransportLongLivedConnectionNotBroken(t *testing.T) {
	const maxMessageSize = 1024
	const messageSize = 800
	const numMessages = 200 // cumulative 160,000 bytes, ~156x the limit

	// Build a message that compresses at a realistic (modest) ratio, not the
	// near-1000:1 of a bomb, so the amplification-ratio guard leaves it alone.
	msg := make([]byte, messageSize)
	for i := range msg {
		msg[i] = byte(i*7 + 3)
	}

	writeBuf := NewTMemoryBuffer()
	writer, err := NewTZlibTransport(writeBuf, zlib.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < numMessages; i++ {
		if _, err := writer.Write(msg); err != nil {
			t.Fatal(err)
		}
		// Flush between messages, mirroring how the transport is used across
		// many RPCs on one persistent connection.
		if err := writer.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	compressed := make([]byte, writeBuf.Len())
	copy(compressed, writeBuf.Bytes())

	readBuf := NewTMemoryBuffer()
	readBuf.Write(compressed)
	reader, err := NewTZlibTransport(readBuf, zlib.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	reader.SetTConfiguration(&TConfiguration{MaxMessageSize: maxMessageSize})

	chunk := make([]byte, 256)
	var total int64
	for {
		n, err := reader.Read(chunk)
		total += int64(n)
		if err != nil {
			if protoEx, ok := err.(TProtocolException); ok && protoEx.TypeId() == SIZE_LIMIT {
				t.Fatalf(
					"legitimate long-lived connection was falsely rejected after %d bytes: %v",
					total, err,
				)
			}
			break // io.EOF once the buffer is drained
		}
	}
	if want := int64(messageSize * numMessages); total < want {
		t.Fatalf("read only %d bytes, expected the full %d", total, want)
	}
}
