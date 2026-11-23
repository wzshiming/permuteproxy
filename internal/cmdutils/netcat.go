package cmdutils

// Netcat command templates: %h is the host, or the socket path for unix, and %p the port.
const (
	NetcatDialTCP    = "nc %h %p"
	NetcatListenTCP  = "nc -l %h %p"
	NetcatDialUnix   = "nc -U %h"
	NetcatListenUnix = "nc -Ul %h"
	NetcatDialUDP    = "nc -u -w 30 %h %p"
)
