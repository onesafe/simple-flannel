package backend

import (
	"net"
	"sync"

	"github.com/onesafe/simple-flannel/subnet"
	"golang.org/x/net/context"
)

type ExternalInterface struct {
	Iface     *net.Interface
	IfaceAddr net.IP
	ExtAddr   net.IP
}

type SimpleNetwork struct {
	SubnetLease *subnet.Lease
	ExtIface    *ExternalInterface
}

type Backend interface {
	RegisterNetwork(ctx context.Context, wg sync.WaitGroup, config *subnet.Config) (Network, error)
}

type Network interface {
	Lease() *subnet.Lease
	MTU() int
	Run(ctx context.Context)
}

type BackendCtor func(sm subnet.Manager, ei *ExternalInterface) (Backend, error)
