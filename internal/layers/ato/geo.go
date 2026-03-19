package ato

import (
	"net"
	"sync"
)

// LocationDB provides IP to location lookup.
type LocationDB struct {
	mu      sync.RWMutex
	entries map[string]*GeoLocation // IP prefix -> location
}

// NewLocationDB creates a new location database.
func NewLocationDB() *LocationDB {
	return &LocationDB{
		entries: make(map[string]*GeoLocation),
	}
}

// Lookup returns the location for an IP.
func (db *LocationDB) Lookup(ip net.IP) *GeoLocation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Try exact match
	if loc, ok := db.entries[ip.String()]; ok {
		return loc
	}

	// Try /24 prefix for IPv4
	if ip4 := ip.To4(); ip4 != nil {
		prefix := string(ip4[:3]) + ".0/24"
		if loc, ok := db.entries[prefix]; ok {
			return loc
		}
	}

	return nil
}

// Add adds a location entry.
func (db *LocationDB) Add(cidr string, loc *GeoLocation) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.entries[cidr] = loc
}
