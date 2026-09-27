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
	"errors"
	"testing"
)

func TestCompactProtocolVarintRejectsOverlong(t *testing.T) {
	// 11 continuation bytes (bit 7 set), no terminating byte
	payload := bytes.Repeat([]byte{0x80}, 11)
	trans := NewTMemoryBufferLen(len(payload))
	trans.Write(payload)
	p := NewTCompactProtocol(trans)
	_, err := p.readVarint64()
	if err == nil {
		t.Fatal("expected error for varint over 10 bytes, got nil")
	}
}

func TestCompactProtocolVarintAcceptsValid10Byte(t *testing.T) {
	// 9 continuation bytes followed by a terminating byte
	payload := append(bytes.Repeat([]byte{0x80}, 9), 0x01)
	trans := NewTMemoryBufferLen(len(payload))
	trans.Write(payload)
	p := NewTCompactProtocol(trans)
	_, err := p.readVarint64()
	if err != nil {
		t.Fatalf("unexpected error for valid 10-byte varint: %v", err)
	}
}

// endlessContinuationReader yields continuation bytes forever, so an unbounded
// varint decoder never terminates. It gives up loudly instead of hanging the
// test binary.
type endlessContinuationReader struct {
	reads int
}

func (r *endlessContinuationReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.reads++
	if r.reads > 10000 {
		return 0, errors.New("varint decoder read past 10000 continuation bytes without terminating")
	}
	for i := range p {
		p[i] = 0x80
	}
	return len(p), nil
}

func TestCompactProtocolVarintTerminatesOnEndlessStream(t *testing.T) {
	reader := &endlessContinuationReader{}
	p := NewTCompactProtocol(NewStreamTransportR(reader))
	if _, err := p.readVarint64(); err == nil {
		t.Fatal("expected error for endless continuation-byte stream, got nil")
	}
	if reader.reads == 0 {
		t.Fatal("expected the decoder to read from the stream")
	}
	if reader.reads > 10000 {
		t.Fatal("varint decoder did not stop reading the endless stream")
	}
}

func TestReadWriteCompactProtocol(t *testing.T) {
	ReadWriteProtocolTest(t, NewTCompactProtocolFactory())

	transports := []TTransport{
		NewTMemoryBuffer(),
		NewStreamTransportRW(bytes.NewBuffer(make([]byte, 0, 16384))),
		NewTFramedTransport(NewTMemoryBuffer()),
	}

	newTZlibTransport := func(trans TTransport, level int) *TZlibTransport {
		t.Helper()
		zlibTrans, err := NewTZlibTransport(trans, level)
		if err != nil {
			t.Fatalf("NewTZlibTransport returned error: %v", err)
		}
		return zlibTrans
	}

	zlib0 := newTZlibTransport(NewTMemoryBuffer(), 0)
	zlib6 := newTZlibTransport(NewTMemoryBuffer(), 6)
	zlib9 := newTZlibTransport(NewTFramedTransport(NewTMemoryBuffer()), 9)
	transports = append(transports, zlib0, zlib6, zlib9)

	for _, trans := range transports {
		p := NewTCompactProtocol(trans)
		ReadWriteBool(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteByte(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteI16(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteI32(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteI64(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteDouble(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteString(t, p, trans)
		p = NewTCompactProtocol(trans)
		ReadWriteBinary(t, p, trans)
		trans.Close()
	}
}
