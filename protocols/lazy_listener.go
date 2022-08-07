package protocols

type lazyListener struct {
	newListener func() (Listener, error)
	listener    Listener
}

func NewLazyListener(newListener func() (Listener, error)) Listener {
	return &lazyListener{
		newListener: newListener,
	}
}

func (l *lazyListener) getListener() (Listener, error) {
	if l.listener == nil {
		listener, err := l.newListener()
		if err != nil {
			return nil, err
		}
		l.listener = listener
	}
	return l.listener, nil
}

func (l *lazyListener) Accept() (Conn, error) {
	listener, err := l.getListener()
	if err != nil {
		return nil, err
	}
	return listener.Accept()
}

func (l *lazyListener) Close() error {
	if l.listener == nil {
		return nil
	}
	return l.listener.Close()
}

var nullAddr = NewAddr("none", "none")

func (l *lazyListener) Addr() Addr {
	if l.listener == nil {
		return nullAddr
	}
	return l.listener.Addr()
}
