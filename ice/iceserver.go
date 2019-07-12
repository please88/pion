package ice


import (
	"encoding/binary"
	"io"
	"net"
	"log"
	"strings"

	"github.com/pion/stun"
)


type Iceserver struct{
	IP net.IP
	Port int
	live bool
	
	agentMap map[string]*Agent
}

var instance *Iceserver = nil

func newIceserver(port int) *Iceserver {
	
	s := &Iceserver{
		Port:			port,
		live:			false,
		agentMap:		make(map[string]*Agent),
	}
	
	//look for local ip addr
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(err)
		return nil
	}
	
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Print(err)
			continue
		}
		
		for _, addr := range addrs {
			var ip net.IP
			switch addr := addr.(type) {
			case *net.IPNet:
				ip = addr.IP
			case *net.IPAddr:
				ip = addr.IP
			}
			
			if ip == nil || ip.IsLoopback() {
				continue
			}

			if ipv4 := ip.To4(); ipv4 != nil {
				log.Printf("local ipv4 %s", ipv4)
				s.IP = ip
				return s;
			} 
		}
	}

	return nil;
}

func GetIceServer() *Iceserver {
	if instance == nil {
		instance = newIceserver(20002)
	}
	return instance
}

func (s *Iceserver) AddAgent(a *Agent){

	localUfrag, _ := a.GetLocalUserCredentials()
	if _, ok := s.agentMap[localUfrag]; ok {
	    log.Printf("agent %s in map", localUfrag)
		return
	} 
	
	s.agentMap[localUfrag] = a;
}

func (s *Iceserver) RmvAgent(a *Agent){

	localUfrag, _ := a.GetLocalUserCredentials()
	if _, ok := s.agentMap[localUfrag]; !ok {
	    log.Printf("agent %s does not in map", localUfrag)
		return
	} 
	
	delete(s.agentMap, localUfrag)
}

func (s *Iceserver) Start(){
	s.live = true
	
	log.Printf("Iceserver listen %s:%d\n", s.IP, s.Port)
	tcpaddr := &net.TCPAddr{IP: s.IP, Port: s.Port}
	tcplisten, err := net.ListenTCP("tcp", tcpaddr);
	if err != nil {
		log.Printf("Failed to listen tcp socket: %s %d: %v\n", s.IP, s.Port, err)
		return
	}

	for s.live {
		conn, err3 := tcplisten.Accept();
		if err3 != nil {
		    continue;
		}
		
		log.Print("get a conn ", conn.RemoteAddr())
	    go s.handleConn(conn);
	 }
}

func (s *Iceserver) handleConn(conn net.Conn){

	var icebinding = false
	var agent *Agent = nil
	
	for !icebinding {
		lenBuffer := make([]byte, 2)
		_, err0 := io.ReadFull(conn, lenBuffer)
		msglen := binary.BigEndian.Uint16(lenBuffer)
		if err0 != nil {
			log.Printf("read head 2 bytes, err %v", err0)
			return
		}

		// log.Printf("read %d byte, msglen %d", n0, msglen)
		buffer := make([]byte, msglen)
		n, err := io.ReadFull(conn, buffer)
		if err != nil {
			log.Printf("read %d bytes, err %v", msglen, err)
			return
		}
		// log.Printf("read %d byte, msglen %d", n, msglen)
		
		if stun.IsSTUN(buffer[:n]) {
			var m *stun.Message
			m, err = stun.NewMessage(buffer[:n])
			if err != nil {
				log.Print("Failed to handle decode ICE, ", err)
				return
			}
			
			log.Printf("stun message Class %s, Method %s, TransactionID %s", m.Class.String(), m.Method.String(), m.TransactionID)
			// for _, v := range m.Attributes {
			// 	log.Printf("stun message attribute %s", v.Type.String())
			// }
	
			usernameAttr := &stun.Username{}
			usernameRawAttr, usernameFound := m.GetOneAttribute(stun.AttrUsername)
		
			if !usernameFound {
				log.Print("inbound packet missing Username")
				return
			} else if err := usernameAttr.Unpack(m, usernameRawAttr); err != nil {
				log.Print("Unpack Username failed", err)
				return 
			}
	
			// log.Printf("incoming stun request Username %s", usernameAttr.Username)
			userfrags := strings.Split(usernameAttr.Username, ":")
			localUfrag := userfrags[0]
			
			var ok bool
			if agent, ok = s.agentMap[localUfrag]; !ok {
			    log.Printf("can not find user name %s in agent map", localUfrag)
				return
			}
			
			if agent.IceConn == nil{
				agent.IceConn = conn	
			}
			
			candidates := agent.localCandidates[NetworkTypeTCP4]
			// log.Printf("candidates number %d", len(candidates))
			if len(candidates) > 0 {
				agent.handleInbound(m, candidates[0], conn.RemoteAddr())
			}
		} else {
			if agent != nil {
				// NOTE This will return packetio.ErrFull if the buffer ever manages to fill up.
				_, err = agent.buffer.Write(buffer[:n])
				if err != nil {
					log.Printf("failed to write packet", err)
				}
			}
		}


	}
}

