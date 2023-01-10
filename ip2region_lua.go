package ip2region

import "github.com/vela-security/vela-public/lua"

func (r *region) startL(L *lua.LState) int {
	xEnv.Start(L, r).From(L.CodeVM()).Do()
	return 0
}

func (r *region) defaultL(L *lua.LState) int {
	xEnv.WithRegion(r)
	return 0
}

func (r *region) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "start":
		return lua.NewFunction(r.startL)
	case "default":
		return lua.NewFunction(r.defaultL)

	}

	return lua.LNil
}
