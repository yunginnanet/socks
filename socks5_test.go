package socks

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/h12w/go-socks5"
	"github.com/phayes/freeport"
)

func httpTestServer(t *testing.T) *http.Server {
	t.Helper()
	var err error
	httpTestPort, err := freeport.GetFreePort()
	t.Logf("http test server port: %d", httpTestPort)
	if err != nil {
		panic(err)
	}
	s := &http.Server{
		Addr: ":" + strconv.Itoa(httpTestPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, err = w.Write([]byte("hello")); err != nil {
				t.Fatalf("write response failed: %v", err)
			}
		}),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		if err := s.ListenAndServe(); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
	tcpReady(httpTestPort, 2*time.Second)
	return s
}

func newTestSocksServer(withAuth bool) (port int) {
	authenticator := socks5.Authenticator(socks5.NoAuthAuthenticator{})
	if withAuth {
		authenticator = socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				"test_user": "test_pass",
			},
		}
	}
	conf := &socks5.Config{
		Logger: log.New(io.Discard, "", log.LstdFlags),
		AuthMethods: []socks5.Authenticator{
			authenticator,
		},
	}

	srv, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	socksTestPort, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	go func() {
		if err = srv.ListenAndServe("tcp", "0.0.0.0:"+strconv.Itoa(socksTestPort)); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
	tcpReady(socksTestPort, 2*time.Second)
	return socksTestPort
}

func TestSocks(t *testing.T) {
	closeBody := func(resp *http.Response) {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body failed: %v", err)
		}
	}

	t.Run("TestSocks5Anonymous", func(t *testing.T) {
		socksTestPort := newTestSocksServer(false)
		dialSocksProxy := Dial(fmt.Sprintf("socks5://127.0.0.1:%d?timeout=5s", socksTestPort))
		tr := &http.Transport{Dial: dialSocksProxy}
		httpClient := &http.Client{Transport: tr}
		resp, err := httpClient.Get(fmt.Sprintf("http://localhost" + httpTestServer(t).Addr))
		if err != nil {
			t.Fatalf("expect response hello but got %s", err)
		}

		defer closeBody(resp)

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("expect response hello but got %s", err)
		}
		if string(respBody) != "hello" {
			t.Fatalf("expect response hello but got %s", respBody)
		}
	})
	t.Run("TestSocks5AnonymousWithConn", func(t *testing.T) {
		socksTestPort := newTestSocksServer(false)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksTestPort), 5*time.Second)
		if err != nil {
			t.Fatalf("dial socks5 proxy failed: %v", err)
		}
		dialSocksProxy := DialWithConn(fmt.Sprintf("socks5://127.0.0.1:%d?timeout=5s", socksTestPort), conn)
		tr := &http.Transport{Dial: dialSocksProxy}
		httpClient := &http.Client{Transport: tr}
		resp, err := httpClient.Get(fmt.Sprintf("http://localhost" + httpTestServer(t).Addr))
		if err != nil {
			t.Fatalf("expect response hello but got %s", err)
		}

		defer closeBody(resp)

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		if string(respBody) != "hello" {
			t.Fatalf("expect response hello but got %s", respBody)
		}
	})

	t.Run("TestSocks5Auth", func(t *testing.T) {
		socksTestPort := newTestSocksServer(true)
		dialSocksProxy := Dial(fmt.Sprintf("socks5://test_user:test_pass@127.0.0.1:%d?timeout=5s", socksTestPort))
		tr := &http.Transport{Dial: dialSocksProxy}
		httpClient := &http.Client{Transport: tr}
		resp, err := httpClient.Get(fmt.Sprintf("http://localhost" + httpTestServer(t).Addr))
		if err != nil {
			t.Fatalf("expect response hello but got %s", err)
		}

		defer closeBody(resp)

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("expect response hello but got %s", err)
		}
		if string(respBody) != "hello" {
			t.Fatalf("expect response hello but got %s", respBody)
		}
	})
}
func tcpReady(port int, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), timeout)
	if err != nil {
		panic(err)
	}
	_ = conn.Close()
}
