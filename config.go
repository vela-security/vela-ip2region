package ip2region

import (
	"fmt"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
)

type config struct {
	name   string
	method string //file , index , memory
	xdb    string
}

func newConfig(L *lua.LState) *config {
	tab := L.CheckTable(1)
	cfg := &config{method: "index"}
	tab.Range(func(key string, val lua.LValue) {
		cfg.NewIndex(L, key, val)
	})

	if e := cfg.verify(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}
	return cfg
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		cfg.name = val.String()

	case "xdb":
		cfg.xdb = val.String()

	case "method":
		cfg.method = val.String()
	default:
		L.RaiseError("invalid %s config invalid", key)
		return

	}

}

func (cfg *config) verify() error {
	if e := auxlib.Name(cfg.name); e != nil {
		return e
	}

	switch cfg.method {
	case "file", "index", "memory":
	//ok
	default:
		return fmt.Errorf("invalid ip2region method  got %v", cfg.method)
	}

	return nil
}
