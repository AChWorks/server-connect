package sc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Test-only SOCKS UDP witnesses never forward a datagram to the Internet.
func (s *domainDNSSOCKS) serveUDP(control net.Conn) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
	reply = binary.BigEndian.AppendUint16(reply, uint16(port))
	if _, err = control.Write(reply); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, client, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			address, _, payload, offset, err := domainDNSUDPDecode(buffer[:n])
			if err != nil || len(payload) == 0 {
				continue
			}
			if address != "76.76.21.21" && address != "2606:4700:1111::1" {
				continue
			}
			s.events <- domainDNSWitness{Path: s.path, Destination: address}
			response := append(append([]byte{}, buffer[:offset]...), s.path...)
			udp.WriteToUDP(response, client)
		}
	}()
	b := make([]byte, 1)
	control.Read(b)
	udp.Close()
	<-done
}
func domainDNSUDPDecode(data []byte) (address string, port int, payload []byte, offset int, err error) {
	if len(data) < 7 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
		return "", 0, nil, 0, fmt.Errorf("invalid SOCKS UDP header")
	}
	reader := bytes.NewReader(data[4:])
	address, err = domainDNSReadSOCKSAddress(reader, data[3])
	if err != nil {
		return
	}
	p := make([]byte, 2)
	if _, err = io.ReadFull(reader, p); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(p))
	offset = len(data) - reader.Len()
	payload = data[offset:]
	return
}
func domainDNSUDPAssociate(proxyPort int) (net.Conn, *net.UDPConn, *net.UDPAddr, error) {
	control, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	failed := true
	defer func() {
		if failed {
			control.Close()
		}
	}()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	control.Write([]byte{5, 1, 0})
	head := make([]byte, 2)
	if _, err = io.ReadFull(control, head); err != nil || head[0] != 5 || head[1] != 0 {
		return nil, nil, nil, fmt.Errorf("UDP auth: %v", err)
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	response := make([]byte, 4)
	if _, err = io.ReadFull(control, response); err != nil || response[1] != 0 {
		return nil, nil, nil, fmt.Errorf("UDP associate: %v", err)
	}
	address, err := domainDNSReadSOCKSAddress(control, response[3])
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err = io.ReadFull(control, head); err != nil {
		return nil, nil, nil, err
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || (!ip.IsLoopback() && !ip.IsUnspecified()) {
		return nil, nil, nil, fmt.Errorf("unexpected UDP relay")
	}
	relay := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(head))}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, nil, err
	}
	control.SetDeadline(time.Time{})
	failed = false
	return control, udp, relay, nil
}
func domainDNSUDPRequest(udp *net.UDPConn, relay *net.UDPAddr, address netip.Addr, port int, payload []byte) ([]byte, error) {
	typ := byte(1)
	if address.Is6() {
		typ = 4
	}
	data := []byte{0, 0, 0, typ}
	data = append(data, address.AsSlice()...)
	data = binary.BigEndian.AppendUint16(data, uint16(port))
	data = append(data, payload...)
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := udp.WriteToUDP(data, relay); err != nil {
		return nil, err
	}
	reply := make([]byte, 4096)
	n, source, err := udp.ReadFromUDP(reply)
	if err != nil {
		return nil, err
	}
	if !source.IP.Equal(relay.IP) || source.Port != relay.Port {
		return nil, fmt.Errorf("foreign SOCKS UDP relay")
	}
	_, actualPort, result, _, err := domainDNSUDPDecode(reply[:n])
	if err != nil || actualPort != port {
		return nil, fmt.Errorf("uncorrelated UDP response: %v", err)
	}
	return append([]byte{}, result...), nil
}
