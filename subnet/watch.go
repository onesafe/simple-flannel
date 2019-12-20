package subnet

import (
	"time"

	log "github.com/golang/glog"
	"github.com/onesafe/simple-flannel/pkg/ip"
	"golang.org/x/net/context"
)

// WatchLeases performs a long term watch of the given network's subnet leases
// and communicates addition/deletion events on receiver channel. It takes care
// of handling "fall-behind" logic where the history window has advanced too far
// and it needs to diff the latest snapshot with its saved state and generate events
/**
  监控整个子网subnets
  ownLease 是节点自己的租约

  reset 可以理解为全量，就是刚启动的时候，拿到全量的subnets数据
  update 可以理解为增量，当启动后，拿到所有的subnets数据后。这个时候会监听事件
*/
func WatchLeases(ctx context.Context, sm Manager, ownLease *Lease, receiver chan []Event) {
	lw := &leaseWatcher{
		ownLease: ownLease,
	}
	var cursor interface{}

	/**
	  当cursor为nil时，也就是第一次for循环的时候，res.Event是0，拿到的是所有subnet信息，这个时候执行reset。
	  第二次for循环的时候，cursor就有值了，这个时候主要是Watch subnets这个key的变化事件
	*/
	for {
		res, err := sm.WatchLeases(ctx, cursor)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return
			}

			log.Errorf("Watch subnets: %v", err)
			time.Sleep(time.Second)
			continue
		}

		cursor = res.Cursor

		var batch []Event

		if len(res.Events) > 0 {
			batch = lw.update(res.Events)
		} else {
			batch = lw.reset(res.Snapshot)
		}

		if len(batch) > 0 {
			receiver <- batch
		}
	}
}

type leaseWatcher struct {
	ownLease *Lease
	leases   []Lease
}

func (lw *leaseWatcher) reset(leases []Lease) []Event {
	batch := []Event{}

	for _, nl := range leases {
		if lw.ownLease != nil && nl.Subnet.Equal(lw.ownLease.Subnet) {
			continue
		}

		found := false
		for i, ol := range lw.leases {
			if ol.Subnet.Equal(nl.Subnet) {
				lw.leases = deleteLease(lw.leases, i)
				found = true
				break
			}
		}

		if !found {
			// new lease
			batch = append(batch, Event{EventAdded, nl})
		}
	}

	// everything left in sm.leases has been deleted
	for _, l := range lw.leases {
		if lw.ownLease != nil && l.Subnet.Equal(lw.ownLease.Subnet) {
			continue
		}
		batch = append(batch, Event{EventRemoved, l})
	}

	// copy the leases over (caution: don't just assign a slice)
	lw.leases = make([]Lease, len(leases))
	copy(lw.leases, leases)

	return batch
}

func (lw *leaseWatcher) update(events []Event) []Event {
	batch := []Event{}

	for _, e := range events {
		if lw.ownLease != nil && e.Lease.Subnet.Equal(lw.ownLease.Subnet) {
			continue
		}

		switch e.Type {
		case EventAdded:
			batch = append(batch, lw.add(&e.Lease))

		case EventRemoved:
			batch = append(batch, lw.remove(&e.Lease))
		}
	}

	return batch
}

func (lw *leaseWatcher) add(lease *Lease) Event {
	for i, l := range lw.leases {
		if l.Subnet.Equal(lease.Subnet) {
			lw.leases[i] = *lease
			return Event{EventAdded, lw.leases[i]}
		}
	}

	lw.leases = append(lw.leases, *lease)

	return Event{EventAdded, lw.leases[len(lw.leases)-1]}
}

func (lw *leaseWatcher) remove(lease *Lease) Event {
	for i, l := range lw.leases {
		if l.Subnet.Equal(lease.Subnet) {
			lw.leases = deleteLease(lw.leases, i)
			return Event{EventRemoved, l}
		}
	}

	log.Errorf("Removed subnet (%s) was not found", lease.Subnet)
	return Event{EventRemoved, *lease}
}

func deleteLease(l []Lease, i int) []Lease {
	l[i] = l[len(l)-1]
	return l[:len(l)-1]
}

// WatchLease performs a long term watch of the given network's subnet lease
// and communicates addition/deletion events on receiver channel. It takes care
// of handling "fall-behind" logic where the history window has advanced too far
// and it needs to diff the latest snapshot with its saved state and generate events
/**
  监控节点所在的租约

  for循环第一次的时候 cursoe为nil，返回的是Snapshot > 0， 添加事件，后面会更新租约的时间
  for循环第二次、一直到第n次的时候，watch到的就是Event事件。如果是EventAdded，那么更新租约，否则EventRemoved，
  说明租约被回收了，那么停掉flanneld进程，退出
*/
func WatchLease(ctx context.Context, sm Manager, sn ip.IP4Net, receiver chan Event) {
	var cursor interface{}

	for {
		wr, err := sm.WatchLease(ctx, sn, cursor)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return
			}

			log.Errorf("Subnet watch failed: %v", err)
			time.Sleep(time.Second)
			continue
		}

		if len(wr.Snapshot) > 0 {
			receiver <- Event{
				Type:  EventAdded,
				Lease: wr.Snapshot[0],
			}
		} else {
			receiver <- wr.Events[0]
		}

		cursor = wr.Cursor
	}
}
