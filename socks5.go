package socks

import (
	"errors"
	"net"
)

func (sesh *session) handshake5(conn net.Conn, targetAddr string) (req *requestBuilder, err error) {
	req = newRequestBuilder()

	version := byte(5) // socks version 5
	method := byte(0)  // method 0: no authentication (only anonymous access supported for now)
	if sesh.Auth != nil {
		method = 2 // method 2: username/password
	}

	// version identifier/method selection request
	req.MustWriteByte(version)
	req.MustWriteByte(1) // number of methods
	req.MustWriteByte(method)

	resp, err := sesh.sendReceive(conn, req.Bytes())

	switch {
	case err != nil:
		return
	case len(resp) != 2:
		err = errors.New("server does not respond properly")
	case resp[0] != 5:
		err = errors.New("server does not support Socks 5")
	case resp[1] != method:
		err = errors.New("socks method negotiation failed")
	default:
		// no-op
	}

	if err != nil {
		return
	}

	if sesh.Auth != nil {
		req.MustReset()
		version = byte(1) // user/password version (1)
		req.MustWriteByte(version)
		req.MustWriteByte(byte(len(sesh.Auth.Username))) // username length
		req.MustWrite([]byte(sesh.Auth.Username))        // username
		req.MustWriteByte(byte(len(sesh.Auth.Password))) // password length
		req.MustWrite([]byte(sesh.Auth.Password))        // password
		resp, err = sesh.sendReceive(conn, req.Bytes())
		switch {
		case err != nil:
			return
		case len(resp) != 2:
			err = errors.New("server does not respond properly")
		case resp[0] != version:
			err = errors.New("server does not support SOCKS5")
		case resp[1] != 0:
			err = errors.New("socks authentication failed")
		default:
			// fmt.Println("socks authentication succeeded")
			// authentication succeeded
		}
		if err != nil {
			return
		}
	}

	// detail request
	var host string
	var port uint16
	host, port, err = splitHostPort(targetAddr)
	if err != nil {
		return
	}
	req.MustReset()
	req.MustWriteByte(5)               // socks version 5
	req.MustWriteByte(1)               // command 1 (CONNECT)
	req.MustWriteByte(0)               // reserved
	req.MustWriteByte(3)               // address type 3 (domain name)
	req.MustWriteByte(byte(len(host))) // length of domain name
	req.MustWrite([]byte(host))        // domain name
	req.MustWriteByte(byte(port >> 8)) // higher byte of destination port
	req.MustWriteByte(byte(port))      // lower byte of destination port (big endian)

	return
}

func (sesh *session) dialSocks5(targetAddr string) (_ net.Conn, err error) {
	conn, err := sesh.internalDial()
	if err != nil {
		return nil, err
	}

	var req *requestBuilder

	if req, err = sesh.handshake5(conn, targetAddr); err != nil {
		return nil, err
	}

	var resp []byte
	resp, err = sesh.sendReceive(conn, req.final())

	switch {
	case err != nil:
		return
	case len(resp) != 10:
		return nil, errors.New("server does not respond properly")
	case resp[1] != 0:
		return nil, errors.New("can't complete SOCKS5 connection")
	default:
		// no-op
	}

	return conn, nil
}
