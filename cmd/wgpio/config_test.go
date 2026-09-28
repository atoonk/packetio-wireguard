package main

import (
	"strings"
	"testing"
)

func TestWgConfToUAPI(t *testing.T) {
	conf := `
[Interface]
PrivateKey = YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
Address = 10.0.0.1/24   # wg-quick only, ignored

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.200.3.0/24, 10.154.0.1
Endpoint = 10.131.0.3:51820
PersistentKeepalive = 25
`
	got, port, err := wgConfToUAPI(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	want := "private_key=6009f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669\npublic_key=c53201039adba14be71f886da1d8dbe9eebded08cb111b75340078999aa9f038\nallowed_ip=10.200.3.0/24\nallowed_ip=10.154.0.1/32\n" +
		"endpoint=10.131.0.3:51820\npersistent_keepalive_interval=25\n"
	if got != want || port != 51820 {
		t.Fatalf("got port %d:\n%s\nwant:\n%s", port, got, want)
	}
	if _, _, err := wgConfToUAPI(strings.NewReader("[Interface]\nPrivateKey = nope\n")); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, _, err := wgConfToUAPI(strings.NewReader("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n")); err == nil {
		t.Fatal("missing private key accepted")
	}
}
