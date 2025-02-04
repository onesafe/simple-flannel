package etcdv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sync"
	"time"

	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	log "github.com/golang/glog"
	"golang.org/x/net/context"

	"github.com/onesafe/simple-flannel/pkg/ip"
	. "github.com/onesafe/simple-flannel/subnet"
)

var (
	errTryAgain = errors.New("try again")
)

type Registry interface {
	getNetworkConfig(ctx context.Context) (string, error)
	getSubnets(ctx context.Context) ([]Lease, uint64, error)
	getSubnet(ctx context.Context, sn ip.IP4Net) (*Lease, uint64, error)
	createSubnet(ctx context.Context, sn ip.IP4Net, attrs *LeaseAttrs, ttl time.Duration) (time.Time, error)
	updateSubnet(ctx context.Context, sn ip.IP4Net, attrs *LeaseAttrs, ttl time.Duration, asof uint64) (time.Time, error)
	deleteSubnet(ctx context.Context, sn ip.IP4Net) error
	watchSubnets(ctx context.Context, since uint64) (Event, uint64, error)
	watchSubnet(ctx context.Context, since uint64, sn ip.IP4Net) (Event, uint64, error)
}

type EtcdConfig struct {
	Endpoints []string
	Keyfile   string
	Certfile  string
	CAFile    string
	Prefix    string
	Username  string
	Password  string
}

type etcdNewFunc func(c *EtcdConfig) (etcd.KeysAPI, error)

// 实现Registry接口
type etcdSubnetRegistry struct {
	cliNewFunc   etcdNewFunc
	mux          sync.Mutex
	cli          etcd.KeysAPI
	etcdCfg      *EtcdConfig
	networkRegex *regexp.Regexp
}

func newEtcdClient(c *EtcdConfig) (etcd.KeysAPI, error) {
	tlsInfo := transport.TLSInfo{
		CertFile: c.Certfile,
		KeyFile:  c.Keyfile,
		CAFile:   c.CAFile,
	}

	t, err := transport.NewTransport(tlsInfo, time.Second)
	if err != nil {
		return nil, err
	}

	cli, err := etcd.New(etcd.Config{
		Endpoints: c.Endpoints,
		Transport: t,
		Username:  c.Username,
		Password:  c.Password,
	})
	if err != nil {
		return nil, err
	}

	return etcd.NewKeysAPI(cli), nil
}

// 根据etcdConfig来创建 EtcdSubnetRegistry， cliNewFunc默认传nil的进来
func newEtcdSubnetRegistry(config *EtcdConfig, cliNewFunc etcdNewFunc) (Registry, error) {
	r := &etcdSubnetRegistry{
		etcdCfg:      config,
		networkRegex: regexp.MustCompile(config.Prefix + `/([^/]*)(/|/config)?$`),
	}
	if cliNewFunc != nil {
		r.cliNewFunc = cliNewFunc
	} else {
		r.cliNewFunc = newEtcdClient
	}

	var err error
	r.cli, err = r.cliNewFunc(config)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (esr *etcdSubnetRegistry) getNetworkConfig(ctx context.Context) (string, error) {
	key := path.Join(esr.etcdCfg.Prefix, "config")
	resp, err := esr.client().Get(ctx, key, &etcd.GetOptions{Quorum: true})
	if err != nil {
		return "", err
	}
	return resp.Node.Value, nil
}

// getSubnets queries etcd to get a list of currently allocated leases for a given network.
// It returns the leases along with the "as-of" etcd-index that can be used as the starting
// point for etcd watch.
func (esr *etcdSubnetRegistry) getSubnets(ctx context.Context) ([]Lease, uint64, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets")
	resp, err := esr.client().Get(ctx, key, &etcd.GetOptions{Recursive: true, Quorum: true})
	if err != nil {
		if etcdErr, ok := err.(etcd.Error); ok && etcdErr.Code == etcd.ErrorCodeKeyNotFound {
			// key not found: treat it as empty set
			return []Lease{}, etcdErr.Index, nil
		}
		return nil, 0, err
	}

	leases := []Lease{}
	for _, node := range resp.Node.Nodes {
		l, err := nodeToLease(node)
		if err != nil {
			log.Warningf("Ignoring bad subnet node: %v", err)
			continue
		}

		leases = append(leases, *l)
	}

	return leases, resp.Index, nil
}

func (esr *etcdSubnetRegistry) getSubnet(ctx context.Context, sn ip.IP4Net) (*Lease, uint64, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	resp, err := esr.client().Get(ctx, key, &etcd.GetOptions{Quorum: true})
	if err != nil {
		return nil, 0, err
	}

	l, err := nodeToLease(resp.Node)
	return l, resp.Index, err
}

func (esr *etcdSubnetRegistry) createSubnet(ctx context.Context, sn ip.IP4Net, attrs *LeaseAttrs, ttl time.Duration) (time.Time, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	value, err := json.Marshal(attrs)
	if err != nil {
		return time.Time{}, err
	}

	opts := &etcd.SetOptions{
		PrevExist: etcd.PrevNoExist,
		TTL:       ttl,
	}

	resp, err := esr.client().Set(ctx, key, string(value), opts)
	if err != nil {
		return time.Time{}, err
	}

	exp := time.Time{}
	if resp.Node.Expiration != nil {
		exp = *resp.Node.Expiration
	}

	return exp, nil
}

func (esr *etcdSubnetRegistry) updateSubnet(ctx context.Context, sn ip.IP4Net, attrs *LeaseAttrs, ttl time.Duration, asof uint64) (time.Time, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	value, err := json.Marshal(attrs)
	if err != nil {
		return time.Time{}, err
	}

	resp, err := esr.client().Set(ctx, key, string(value), &etcd.SetOptions{
		PrevIndex: asof,
		TTL:       ttl,
	})
	if err != nil {
		return time.Time{}, err
	}

	exp := time.Time{}
	if resp.Node.Expiration != nil {
		exp = *resp.Node.Expiration
	}

	return exp, nil
}

func (esr *etcdSubnetRegistry) deleteSubnet(ctx context.Context, sn ip.IP4Net) error {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	_, err := esr.client().Delete(ctx, key, nil)
	return err
}

func (esr *etcdSubnetRegistry) watchSubnets(ctx context.Context, since uint64) (Event, uint64, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets")
	opts := &etcd.WatcherOptions{
		AfterIndex: since,
		Recursive:  true,
	}
	e, err := esr.client().Watcher(key, opts).Next(ctx)
	if err != nil {
		return Event{}, 0, err
	}

	evt, err := parseSubnetWatchResponse(e)
	return evt, e.Node.ModifiedIndex, err
}

func (esr *etcdSubnetRegistry) watchSubnet(ctx context.Context, since uint64, sn ip.IP4Net) (Event, uint64, error) {
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	opts := &etcd.WatcherOptions{
		AfterIndex: since,
	}

	e, err := esr.client().Watcher(key, opts).Next(ctx)
	if err != nil {
		return Event{}, 0, err
	}

	evt, err := parseSubnetWatchResponse(e)
	return evt, e.Node.ModifiedIndex, err
}

// 加锁的方式获取etcdClient
func (esr *etcdSubnetRegistry) client() etcd.KeysAPI {
	esr.mux.Lock()
	defer esr.mux.Unlock()
	return esr.cli
}

func parseSubnetWatchResponse(resp *etcd.Response) (Event, error) {
	sn := ParseSubnetKey(resp.Node.Key)
	if sn == nil {
		return Event{}, fmt.Errorf("%v %q: not a subnet, skipping", resp.Action, resp.Node.Key)
	}

	switch resp.Action {
	case "delete", "expire":
		return Event{
			EventRemoved,
			Lease{Subnet: *sn},
		}, nil

	default:
		attrs := &LeaseAttrs{}
		err := json.Unmarshal([]byte(resp.Node.Value), attrs)
		if err != nil {
			return Event{}, err
		}

		exp := time.Time{}
		if resp.Node.Expiration != nil {
			exp = *resp.Node.Expiration
		}

		evt := Event{
			EventAdded,
			Lease{
				Subnet:     *sn,
				Attrs:      *attrs,
				Expiration: exp,
			},
		}
		return evt, nil
	}
}

/**
  etcd的租约机制：
    新建一个过期时间为120秒的租约。
    新建key，并为该key指定租约
    租约到期后，对应的key会被自动删除

    在租约即将到期的时候，可续约
*/
func nodeToLease(node *etcd.Node) (*Lease, error) {
	sn := ParseSubnetKey(node.Key)
	if sn == nil {
		return nil, fmt.Errorf("failed to parse subnet key %s", node.Key)
	}

	attrs := &LeaseAttrs{}
	if err := json.Unmarshal([]byte(node.Value), attrs); err != nil {
		return nil, err
	}

	exp := time.Time{}
	if node.Expiration != nil {
		exp = *node.Expiration
	}

	lease := Lease{
		Subnet:     *sn,
		Attrs:      *attrs,
		Expiration: exp,
		Asof:       node.ModifiedIndex,
	}

	return &lease, nil
}
