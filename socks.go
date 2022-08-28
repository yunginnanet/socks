// Copyright 2012, Hailiang Wang. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package socks implements a SOCKS (SOCKS4, SOCKS4A and SOCKS5) proxy client.

A complete example using this package:

	package main

	import (
		"h12.io/socks"
		"fmt"
		"net/http"
		"io/ioutil"
	)

	func main() {
		dialSocksProxy := socks.Dial("socks5://127.0.0.1:1080?timeout=5s")
		tr := &http.Transport{Dial: dialSocksProxy}
		httpClient := &http.Client{Transport: tr}

		bodyText, err := TestHttpsGet(httpClient, "https://h12.io/about")
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Print(bodyText)
	}

	func TestHttpsGet(c *http.Client, url string) (bodyText string, err error) {
		resp, err := c.Get(url)
		if err != nil { return }
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil { return }
		bodyText = string(body)
		return
	}
*/
package socks // import "h12.io/socks"

import (
	"fmt"
	"net"
	"time"
)

// Constants to choose which version of SOCKS protocol to use.
const (
	SOCKS4 = iota
	SOCKS4A
	SOCKS5
)

// DialWithConn returns the dial function to be used in http.Transport object.
// Argument proxyURI should be in the format: "socks5://user:password@127.0.0.1:1080?timeout=5s".
// The protocol could be socks5, socks4 and socks4a. DialWithConn will use the given connection
// to communicate with the proxy server.
func DialWithConn(proxyURI string, conn net.Conn) func(string, string) (net.Conn, error) {
	cfg, err := parse(proxyURI)
	if err != nil {
		return dialError(err)
	}
	cfg.conn = conn
	return cfg.dialFunc()
}

// Dial returns the dial function to be used in http.Transport object.
// Argument proxyURI should be in the format: "socks5://user:password@127.0.0.1:1080?timeout=5s".
// The protocol could be socks5, socks4 and socks4a.
func Dial(proxyURI string) func(string, string) (net.Conn, error) {
	cfg, err := parse(proxyURI)
	if err != nil {
		return dialError(err)
	}
	return cfg.dialFunc()
}

// DialSocksProxy returns the dial function to be used in http.Transport object.
// Argument socksType should be one of SOCKS4, SOCKS4A and SOCKS5.
// Argument proxy should be in this format "127.0.0.1:1080".
func DialSocksProxy(socksType int, proxy string) func(string, string) (net.Conn, error) {
	return (&config{Proto: socksType, Host: proxy}).dialFunc()
}

func (cfg *config) dialFunc() func(string, string) (net.Conn, error) {
	switch cfg.Proto {
	case SOCKS5:
		return func(_, targetAddr string) (conn net.Conn, err error) {
			return cfg.dialSocks5(targetAddr)
		}
	case SOCKS4, SOCKS4A:
		return func(_, targetAddr string) (conn net.Conn, err error) {
			return cfg.dialSocks4(targetAddr)
		}
	}
	return dialError(fmt.Errorf("unknown SOCKS protocol %v", cfg.Proto))
}

func dialError(err error) func(string, string) (net.Conn, error) {
	return func(_, _ string) (net.Conn, error) {
		return nil, err
	}
}

func (cfg *config) internalDial() (conn net.Conn, err error) {
	if cfg.conn != nil {
		err = cfg.conn.SetDeadline(time.Now().Add(cfg.Timeout))
		return cfg.conn, nil
	}
	return net.DialTimeout("tcp", cfg.Host, cfg.Timeout)
}
