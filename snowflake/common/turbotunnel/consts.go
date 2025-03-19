// Package turbotunnel provides support for overlaying a virtual net.PacketConn
// on some other network carrier.
//
// https://github.com/net4people/bbs/issues/9
package turbotunnel

import "errors"

// This magic prefix is how a client opts into turbo tunnel mode. It is just a
// randomly generated byte string.
var Token = [8]byte{0x12, 0x93, 0x60, 0x5d, 0x27, 0x81, 0x75, 0xf5}

// The size of receive and send queues.
const queueSize = 512

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")
