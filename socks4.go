package socks

import (
	"errors"
	"net"
	"time"
)

func (sesh *session) dialSocks4(targetAddr string) (_ net.Conn, err error) {
	socksType := sesh.Proto

	conn, err := sesh.internalDial()
	if err != nil {
		return nil, err
	}

	// connection request
	host, port, err := splitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	ip := net.IPv4(0, 0, 0, 1).To4()
	if socksType == SOCKS4 {
		ip, err = lookupIPv4(host)
		if err != nil {
			return nil, err
		}
	}
	req := newRequestBuilder()
	req.MustWriteByte(4)               // socks version 4
	req.MustWriteByte(1)               // command 1 (CONNECT)
	req.MustWriteByte(byte(port >> 8)) // higher byte of destination port
	req.MustWriteByte(byte(port))      // lower byte of destination port (big endian)

	// target IP address
	req.MustWriteByte(ip[0])
	req.MustWriteByte(ip[1])
	req.MustWriteByte(ip[2])
	req.MustWriteByte(ip[3])

	req.MustWriteByte(0) // user id is empty, anonymous proxy only

	if socksType == SOCKS4A {
		_, _ = req.WriteString(host)
		req.MustWriteByte(0)
	}

	resp, err := sesh.sendReceive(conn, req.final())
	if err != nil {
		return nil, err
	} else if len(resp) != 8 {
		return nil, errors.New("server does not respond properly")
	}
	switch resp[1] {
	case 90:
		// request granted
	case 91:
		return nil, errors.New("socks connection request rejected or failed")
	case 92:
		return nil, errors.New("socks connection request rejected because SOCKS server cannot connect to identd on the client")
	case 93:
		return nil, errors.New("socks connection request rejected because the client program and identd report different user-ids")
	default:
		return nil, errors.New("socks connection request failed, unknown error")
	}
	// clear the deadline before returning
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}
