package cmdutils

// Netcat command templates: %h is the host, or the socket path for unix, and %p the port.
const (
	// NetcatDialTCP is the template that dials TCP.
	NetcatDialTCP = "nc %h %p"
	// NetcatListenTCP is the template that listens on TCP.
	NetcatListenTCP = "nc -l %h %p"
	// NetcatDialUnix is the template that dials a unix socket.
	NetcatDialUnix = "nc -U %h"
	// NetcatListenUnix is the template that listens on a unix socket.
	NetcatListenUnix = "nc -Ul %h"
	// NetcatDialUDP is the template that dials UDP.
	NetcatDialUDP = "nc -u -w 30 %h %p"
)
