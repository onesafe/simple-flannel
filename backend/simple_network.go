package backend

import (
	"golang.org/x/net/context"
	"github.com/onesafe/simple-flannel/subnet"
)

type SimpleNetwork struct {
	SubnetLease *subnet.Lease
	ExtIface    *ExternalInterface
}

func (n *SimpleNetwork) Lease() *subnet.Lease {
	return n.SubnetLease
}

func (n *SimpleNetwork) MTU() int {
	return n.ExtIface.Iface.MTU
}

func (_ *SimpleNetwork) Run(ctx context.Context) {
	<-ctx.Done()
}
