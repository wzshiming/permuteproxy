package protocols

type Define struct {
	Handle
	SchemeInfo
}

func Registry(scheme string, f Define) {
	RegisterScheme(scheme, f.SchemeInfo)
	RegisterHandle(scheme, f.Handle)
}
