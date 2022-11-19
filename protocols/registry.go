package protocols

var (
	schemeInfoData = map[string]SchemeInfo{}
	alias          = map[string]string{}
	reverseAlias   = map[string]string{}
)

func RegisterScheme(scheme string, schemeInfo SchemeInfo) {
	schemeInfoData[scheme] = schemeInfo
}

func RegisterAlias(k, v string) {
	alias[k] = v
}

func RegisterReverseAlias(k, v string) {
	reverseAlias[v] = k
}

func getSchemeInfo(scheme string) (SchemeInfo, bool) {
	info, ok := schemeInfoData[scheme]
	return info, ok
}

func getAlias(scheme string) string {
	if v, ok := alias[scheme]; ok {
		return v
	}
	return scheme
}

func getReverseAlias(scheme string) string {
	if v, ok := reverseAlias[scheme]; ok {
		return v
	}
	return scheme
}
