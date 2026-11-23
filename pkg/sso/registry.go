package sso

import (
	"sort"
	"sync"
)

// Factory builds a Provider from string configuration (e.g. loaded from env or YAML).
type Factory func(cfg map[string]string) (Provider, error)

var (
	driversMu sync.RWMutex
	drivers   = map[string]Factory{}
)

// RegisterDriver registers a named provider factory. It panics on duplicates or nil
// factories, mirroring database/sql.Register semantics (call from init()).
func RegisterDriver(name string, f Factory) {
	driversMu.Lock()
	defer driversMu.Unlock()
	if f == nil {
		panic("sso: RegisterDriver factory is nil")
	}
	if _, dup := drivers[name]; dup {
		panic("sso: RegisterDriver called twice for driver " + name)
	}
	drivers[name] = f
}

// NewProvider instantiates a provider using a registered driver.
func NewProvider(driver string, cfg map[string]string) (Provider, error) {
	driversMu.RLock()
	f, ok := drivers[driver]
	driversMu.RUnlock()
	if !ok {
		return nil, ErrNotFound("unknown provider driver: " + driver)
	}
	return f(cfg)
}

// Drivers returns the sorted names of all registered drivers.
func Drivers() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()
	names := make([]string, 0, len(drivers))
	for n := range drivers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
