package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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
	if err := checkAndInitNft(conn); err != nil {
		return nil, err
	}
	return &Nft{
		Mutex: &sync.Mutex{},
		Conn:  conn,
	}, nil
}

func checkAndInitNft(conn *nftables.Conn) error {
	// Get or create table
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "nat",
	}

	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return err
	}

	tableExists := false
	for _, t := range tables {
		if t.Name == "nat" {
			tableExists = true
			table = t
			break
		}
	}

	if !tableExists {
		table = conn.AddTable(table)
	}

	// Get or create chain
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return err
	}

	chainExists := false
	var chain *nftables.Chain
	for _, c := range chains {
		if c.Table.Name == "nat" && c.Name == "postrouting" {
			chainExists = true
			chain = c
			break
		}
	}

	if !chainExists {
		priority := nftables.ChainPriority(100)
		chain = &nftables.Chain{
			Name:     "postrouting",
			Table:    table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: &priority,
		}
		conn.AddChain(chain)
	}

	// Get or create usermap set
	sets, err := conn.GetSetByName(table, "usermap")
	if err == nil {
		// Set exists, flush its elements
		conn.FlushSet(sets)
	} else {
		// Create new set
		set := &nftables.Set{
			Name:     "usermap",
			Table:    table,
			KeyType:  nftables.TypeMark,
			DataType: nftables.TypeIP6Addr,
		}
		if err := conn.AddSet(set, nil); err != nil {
			return err
		}
	}

	// Check if rule exists, if not create it
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return err
	}

	ruleExists := false
	for _, r := range rules {
		// Check if this is our SNAT rule by examining expressions
		// This is a simplified check
		if len(r.Exprs) > 0 {
			for _, e := range r.Exprs {
				if _, ok := e.(*expr.NAT); ok {
					ruleExists = true
					break
				}
			}
		}
	}

	if !ruleExists {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				// meta mark
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				// lookup in usermap
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   1,
					SetName:        "usermap",
				},
				// snat to
				&expr.NAT{
					Type:       expr.NATTypeSourceNAT,
					Family:     uint32(nftables.TableFamilyIPv6),
					RegAddrMin: 1,
				},
			},
		})
	}

	return conn.Flush()
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
