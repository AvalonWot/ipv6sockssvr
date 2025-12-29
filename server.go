package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/AvalonWot/socks5"
	"github.com/txthinking/runnergroup"
)

type Server struct {
	Addr              string
	SupportedCommands []byte
	Mutex             sync.Locker
	MarkPointer       int
	UserMap           map[string]int
	RunnerGroup       *runnergroup.RunnerGroup
	Nft               *Nft
	IPv6Prefix        net.IP
}

func NewServer(addr, prefix string) (*Server, error) {
	ip := net.ParseIP(prefix)
	if ip == nil || ip.To16() == nil {
		return nil, fmt.Errorf("invalid IPv6 prefix: %s", prefix)
	}
	nft, err := NewNft()
	if err != nil {
		return nil, fmt.Errorf("init nft err: %v", err)
	}
	return &Server{
		Addr:              addr,
		SupportedCommands: []byte{socks5.CmdConnect},
		Mutex:             &sync.Mutex{},
		MarkPointer:       1,
		UserMap:           make(map[string]int, 10000),
		RunnerGroup:       runnergroup.New(),
		Nft:               nft,
		IPv6Prefix:        ip,
	}, nil
}

func (s *Server) Negotiate(rw io.ReadWriter) (string, error) {
	rq, err := socks5.NewNegotiationRequestFrom(rw)
	if err != nil {
		return "", err
	}
	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == socks5.MethodUsernamePassword {
			got = true
		}
	}
	if !got {
		rp := socks5.NewNegotiationReply(socks5.MethodUnsupportAll)
		if _, err := rp.WriteTo(rw); err != nil {
			return "", err
		}
	}
	rp := socks5.NewNegotiationReply(socks5.MethodUsernamePassword)
	if _, err := rp.WriteTo(rw); err != nil {
		return "", err
	}

	urq, err := socks5.NewUserPassNegotiationRequestFrom(rw)
	if err != nil {
		return "", err
	}
	userName := string(urq.Uname)
	if len(userName) == 0 {
		urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
		if _, err := urp.WriteTo(rw); err != nil {
			return "", err
		}
		return "", socks5.ErrUserPassAuth
	}
	urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
	if _, err := urp.WriteTo(rw); err != nil {
		return "", err
	}

	return userName, nil
}

func (s *Server) GetRequest(rw io.ReadWriter) (*socks5.Request, error) {
	r, err := socks5.NewRequestFrom(rw)
	if err != nil {
		return nil, err
	}
	var supported bool
	for _, c := range s.SupportedCommands {
		if r.Cmd == c {
			supported = true
			break
		}
	}
	if !supported {
		var p *socks5.Reply
		if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
			p = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(rw); err != nil {
			return nil, err
		}
		return nil, socks5.ErrUnsupportCmd
	}
	if r.Atyp != socks5.ATYPDomain {
		p := socks5.NewReply(socks5.RepAddressNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		if _, err := p.WriteTo(rw); err != nil {
			return nil, err
		}
		return nil, socks5.ErrUnsupportCmd
	}
	return r, nil
}

func (s *Server) GetOrCreateNat66Mark(user string) (int, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if mark, ok := s.UserMap[user]; ok {
		return mark, nil
	}

	// concat prefix and sha256(user)[24:32] to get a new ipv6 address
	hash := sha256.Sum256([]byte(user))
	suffix := hash[24:32]
	newip := make([]byte, 16)
	copy(newip, s.IPv6Prefix.To16()[:8])
	copy(newip[8:], suffix)

	ip := net.IP(newip)
	mark := s.MarkPointer
	log.Printf("New user: %s -> %s, mark: %d\n", user, ip.String(), mark)
	if err := s.Nft.AddUserMap(mark, ip); err != nil {
		return 0, err
	}
	s.UserMap[user] = mark
	s.MarkPointer++
	return mark, nil
}

func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				c, err := l.AcceptTCP()
				if err != nil {
					return err
				}
				go func(c *net.TCPConn) {
					defer c.Close()
					var user string
					if user, err = s.Negotiate(c); err != nil {
						log.Println(err)
						return
					}
					r, err := s.GetRequest(c)
					if err != nil {
						log.Println(err)
						return
					}
					mark, err := s.GetOrCreateNat66Mark(user)
					if err != nil {
						log.Println(err)
						return
					}
					if err := s.TCPHandle(s, c, r, mark); err != nil {
						log.Println(err)
					}
				}(c)
			}
		},
		Stop: func() error {
			return l.Close()
		},
	})
	return s.RunnerGroup.Wait()
}

func (s *Server) Shutdown() error {
	return s.RunnerGroup.Done()
}

func (h *Server) TCPHandle(s *Server, c *net.TCPConn, r *socks5.Request, mark int) error {
	if r.Cmd != socks5.CmdConnect {
		return socks5.ErrUnsupportCmd
	}
	d := &TcpWithMarkDialer{
		Mark: mark,
	}

	rc, err := r.Connect("tcp6", d, c)
	if err != nil {
		return err
	}
	defer rc.Close()
	go func() {
		var bf [1024 * 2]byte
		for {
			// if s.TCPTimeout != 0 {
			// 	if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
			// 		return
			// 	}
			// }
			i, err := rc.Read(bf[:])
			if err != nil {
				return
			}
			if _, err := c.Write(bf[0:i]); err != nil {
				return
			}
		}
	}()
	var bf [1024 * 2]byte
	for {
		// if s.TCPTimeout != 0 {
		// 	if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
		// 		return nil
		// 	}
		// }
		i, err := c.Read(bf[:])
		if err != nil {
			return nil
		}
		if _, err := rc.Write(bf[0:i]); err != nil {
			return nil
		}
	}
}
