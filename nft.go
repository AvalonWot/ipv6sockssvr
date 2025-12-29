package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
)

type Nft struct {
	Mutex sync.Locker
	Conn  *nftables.Conn
}

func NewNft() (*Nft, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return &Nft{
		Mutex: &sync.Mutex{},
		Conn:  conn,
	}, nil
}

// #deploy the nft tables
// nft add table ip6 nat
// nft add chain ip6 nat postrouting { type nat hook postrouting priority 100 \; }
// nft add map ip6 nat usermap { type mark : ipv6_addr \; }
// nft add rule ip6 nat postrouting snat to meta mark map @usermap

func (n *Nft) AddUserMap(mark int, addr net.IP) error {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	// nft add element ip6 nat usermap { 1234 : 2001:db8:abcd:1234::100 }
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "nat",
	}
	set := &nftables.Set{
		Table:    table,
		Name:     "usermap",
		KeyType:  nftables.TypeInteger,
		DataType: nftables.TypeIP6Addr,
	}

	// mark to 4 bytes
	key := make([]byte, 4)
	key[3] = byte(mark >> 24)
	key[2] = byte(mark >> 16)
	key[1] = byte(mark >> 8)
	key[0] = byte(mark)

	// addr to 16 bytes(IPv6)
	data := addr.To16()
	if data == nil || len(data) != 16 {
		return fmt.Errorf("invalid IPv6 address: %s", addr)
	}

	elem := nftables.SetElement{
		Key: key,
		Val: data,
	}

	err := n.Conn.SetAddElements(set, []nftables.SetElement{elem})
	if err != nil {
		return err
	}
	return n.Conn.Flush()
}
