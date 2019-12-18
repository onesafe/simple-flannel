package simple_flannel

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/onesafe/simple-flannel/pkg/ip"

	"github.com/coreos/pkg/flagutil"
	log "github.com/golang/glog"

	"github.com/onesafe/simple-flannel/backend"
	"github.com/onesafe/simple-flannel/network"
	"github.com/onesafe/simple-flannel/version"

	"github.com/onesafe/simple-flannel/subnet"
	"github.com/onesafe/simple-flannel/subnet/etcdv2"
)

type flagSlice []string

func (t *flagSlice) String() string {
	return fmt.Sprintf("%v", *t)
}

func (t *flagSlice) Set(val string) error {
	*t = append(*t, val)
	return nil
}

type CmdLineOpts struct {
	etcdEndpoints string
	etcdPrefix    string
	etcdKeyfile   string
	etcdCertfile  string
	etcdCAFile    string
	etcdUsername  string
	etcdPassword  string

	help    bool
	version bool

	iface                  flagSlice
	ipMasq                 bool
	subnetFile             string
	subnetDir              string
	publicIP               string
	subnetLeaseRenewMargin int

	healthzIP   string
	healthzPort int

	iptablesResyncSeconds int
	iptablesForwardRules  bool
}

var (
	opts           CmdLineOpts
	errInterrupted = errors.New("interrupted")
	errCanceled    = errors.New("canceled")
	flannelFlags   = flag.NewFlagSet("flannel", flag.ExitOnError)
)

func init() {
	flannelFlags.StringVar(&opts.etcdEndpoints, "etcd-endpoints", "http://127.0.0.1:4001,http://127.0.0.1:2379", "a comma-delimited list of etcd endpoints")
	flannelFlags.StringVar(&opts.etcdPrefix, "etcd-prefix", "/coreos.com/network", "etcd prefix")
	flannelFlags.StringVar(&opts.etcdKeyfile, "etcd-keyfile", "", "SSL key file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdCertfile, "etcd-certfile", "", "SSL certification file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdCAFile, "etcd-cafile", "", "SSL Certificate Authority file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdUsername, "etcd-username", "", "username for BasicAuth to etcd")
	flannelFlags.StringVar(&opts.etcdPassword, "etcd-password", "", "password for BasicAuth to etcd")

	flannelFlags.Var(&opts.iface, "iface", "interface to use (IP or name) for inter-host communication. Can be specified multiple times to check each option in order. Returns the first match found.")
	flannelFlags.StringVar(&opts.subnetFile, "subnet-file", "/run/flannel/subnet.env", "filename where env variables (subnet, MTU, ... ) will be written to")
	flannelFlags.StringVar(&opts.publicIP, "public-ip", "", "IP accessible by other nodes for inter-host communication")
	flannelFlags.IntVar(&opts.subnetLeaseRenewMargin, "subnet-lease-renew-margin", 60, "subnet lease renewal margin, in minutes, ranging from 1 to 1439")
	flannelFlags.BoolVar(&opts.ipMasq, "ip-masq", false, "setup IP masquerade rule for traffic destined outside of overlay network")

	flannelFlags.BoolVar(&opts.version, "version", false, "print version and exit")
	flannelFlags.StringVar(&opts.healthzIP, "healthz-ip", "0.0.0.0", "the IP address for healthz server to listen")
	flannelFlags.IntVar(&opts.healthzPort, "healthz-port", 0, "the port for healthz server to listen(0 to disable)")

	flannelFlags.IntVar(&opts.iptablesResyncSeconds, "iptables-resync", 5, "resync period for iptables rules, in seconds")
	flannelFlags.BoolVar(&opts.iptablesForwardRules, "iptables-forward-rules", true, "add default accept rules to FORWARD chain in iptables")

	// glog will log to tmp files by default. override so all entries
	// can flow into journald (if running under systemd)
	err := flag.Set("logtostderr", "true")
	if err != nil {
		log.Error("flag.Set ", err.Error())
	}

	// Only copy the non file logging options from glog
	copyFlag("v")
	copyFlag("vmodule")
	copyFlag("log_backtrace_at")

	// Define the usage function
	flannelFlags.Usage = usage

	// now parse command line args
	err = flannelFlags.Parse(os.Args[1:])
	if err != nil {
		log.Error("flannelFlags.Parse ", err.Error())
	}
}

func copyFlag(name string) {
	flannelFlags.Var(flag.Lookup(name).Value, flag.Lookup(name).Name, flag.Lookup(name).Usage)
}

func usage() {
	_, err := fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
	if err != nil {
		log.Error("print usage ", err.Error())
	}
	flannelFlags.PrintDefaults()
	os.Exit(0)
}

func newSubnetManager() (subnet.Manager, error) {
	cfg := &etcdv2.EtcdConfig{
		Endpoints: strings.Split(opts.etcdEndpoints, ","),
		Keyfile:   opts.etcdKeyfile,
		Certfile:  opts.etcdCertfile,
		CAFile:    opts.etcdCAFile,
		Prefix:    opts.etcdPrefix,
		Username:  opts.etcdUsername,
		Password:  opts.etcdPassword,
	}

	// Attempt to renew the lease for the subnet specified in the subnetFile
	prevSubnet := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_SUBNET")

	return etcdv2.NewLocalManager(cfg, prevSubnet)
}

func main() {
	var err error

	if opts.version {
		_, err := fmt.Fprintln(os.Stderr, version.Version)
		if err != nil {
			log.Error("print version ", err.Error())
		}
		os.Exit(0)
	}

	err = flagutil.SetFlagsFromEnv(flannelFlags, "FLANNELD")
	if err != nil {
		log.Error("flagutil setFlagsFromEnv ", err.Error())
	}

	// Validate flags
	if opts.subnetLeaseRenewMargin >= 24*60 || opts.subnetLeaseRenewMargin <= 0 {
		log.Error("Invalid subnet-lease-renew-margin option, out of acceptable range")
		os.Exit(1)
	}

	// Work out which interface to use
	var extIface *backend.ExternalInterface

	// Check the default interface only if no interfaces are specified
	if len(opts.iface) == 0 {
		extIface, err = LookupExtIface(opts.publicIP)
		if err != nil {
			log.Error("Failed to find any valid interface to use: ", err)
			os.Exit(1)
		}
	} else {
		// Check explicitly specified interfaces
		for _, iface := range opts.iface {
			extIface, err = LookupExtIface(iface)
			if err != nil {
				log.Infof("Could not find valid interface matching %s: %s", iface, err)
			}

			if extIface != nil {
				break
			}
		}

		if extIface == nil {
			// Exit if any of the specified interfaces do not match
			log.Error("Failed to find interface to use that matches the interfaces and/or regexes provided")
			os.Exit(1)
		}
	}

	sm, err := newSubnetManager()
	if err != nil {
		log.Error("Failed to create SubnetManager: ", err)
		os.Exit(1)
	}
	log.Infof("Created subnet manager: %s", sm.Name())

	// Register for SIGINT and SIGTERM
	// 安装信号处理函数
	log.Info("Installing signal handlers")
	sigs := make(chan os.Signal, 1)

	// 将信号SIGINT 和 SIGTERM转发到sigs
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// This is the main context that everything should run in.
	// All spawned goroutines should exit when cancel is called on this context.
	// Go routines spawned from main.go coordinate using a WaitGroup. This provides a mechanism to allow the shutdownHandler goroutine
	// to block until all the goroutines return . If those goroutines spawn other goroutines then they are responsible for
	// blocking and returning only when cancel() is called.
	/**
	  这是所有内容都应运行的主要上下文。
	  当在此上下文中调用cancel时，所有产生的goroutine都应退出。

	  使用WaitGroup从main.go坐标生成的Go线程。 这提供了一种机制，允许shutdownHandler goroutine阻塞直到所有goroutine返回。
	  如果这些goroutine产生了其他goroutine，则它们负责阻塞，仅在调用cancel（）时返回。
	*/
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		shutdownHandler(ctx, sigs, cancel)
		wg.Done()
	}()

	if opts.healthzPort > 0 {
		// It's not super easy to shutdown the HTTP server so don't attempt to stop it cleanly
		go mustRunHealthz()
	}

	// Fetch the network config (i.e. what backend to use etc..).
	config, err := getConfig(ctx, sm)
	if err == errCanceled {
		wg.Wait()
		os.Exit(0)
	}

	// Create a backend manager then use it to create the backend and register the network with it.
	bm := backend.NewManager(ctx, sm, extIface)

	// 获取对应的backend
	be, err := bm.GetBackend(config.BackendType)
	if err != nil {
		log.Errorf("Error fetching backend: %s", err)
		cancel()
		wg.Wait()
		os.Exit(1)
	}

	// 注册网络, 如果是vxlan的话，创建vxlan设备 newVXLANDevice，然后做其他的操作
	bn, err := be.RegisterNetwork(ctx, wg, config)
	if err != nil {
		log.Errorf("Error registering network: %s", err)
		cancel()
		wg.Wait()
		os.Exit(1)
	}

	// Set up ipMasq if needed
	if opts.ipMasq {
		if err = recycleIPTables(config.Network, bn.Lease()); err != nil {
			log.Errorf("Failed to recycle IPTables rules, %v", err)
			cancel()
			wg.Wait()
			os.Exit(1)
		}
		log.Infof("Setting up masking rules")
		go network.SetupAndEnsureIPTables(network.MasqRules(config.Network, bn.Lease()), opts.iptablesResyncSeconds)
	}

	// Always enables forwarding rules. This is needed for Docker versions >1.13 (https://docs.docker.com/engine/userguide/networking/default_network/container-communication/#container-communication-between-hosts)
	// In Docker 1.12 and earlier, the default FORWARD chain policy was ACCEPT.
	// In Docker 1.13 and later, Docker sets the default policy of the FORWARD chain to DROP.
	if opts.iptablesForwardRules {
		log.Infof("Changing default FORWARD chain policy to ACCEPT")
		go network.SetupAndEnsureIPTables(network.ForwardRules(config.Network.String()), opts.iptablesResyncSeconds)
	}

	if err := WriteSubnetFile(opts.subnetFile, config.Network, opts.ipMasq, bn); err != nil {
		// Continue, even though it failed.
		log.Warningf("Failed to write subnet file: %s", err)
	} else {
		log.Infof("Wrote subnet file to %s", opts.subnetFile)
	}

	// Start "Running" the backend network. This will block until the context is done so run in another goroutine.
	log.Info("Running backend.")
	wg.Add(1)
	go func() {
		bn.Run(ctx)
		wg.Done()
	}()

	sent, err := SdNotify(false, "READY=1")
	if err != nil {
		log.Error("SdNotiry sent: ", sent)
		log.Error("SdNotify err: ", err.Error())
	}

	err = MonitorLease(ctx, sm, bn, &wg)
	if err == errInterrupted {
		// The lease was "revoked" - shut everything down
		cancel()
	}

	log.Info("Waiting for all goroutines to exit")
	// Block waiting for all the goroutines to finish.
	// 主线程调用Wait()方法阻塞，等到所有线程结束
	wg.Wait()

	log.Info("Exiting cleanly...")
	os.Exit(0)
}

//  ------  SdNotify Code forked from Docker project   ----------
//
// SdNotify sends a message to the init daemon. It is common to ignore the error.
// If `unsetEnvironment` is true, the environment variable `NOTIFY_SOCKET`
// will be unconditionally unset.
//
// It returns one of the following:
// (false, nil) - notification not supported (i.e. NOTIFY_SOCKET is unset)
// (false, err) - notification supported, but failure happened (e.g. error connecting to NOTIFY_SOCKET or while sending data)
// (true, nil) - notification supported, data has been sent
func SdNotify(unsetEnvironment bool, state string) (sent bool, err error) {
	socketAddr := &net.UnixAddr{
		Name: os.Getenv("NOTIFY_SOCKET"),
		Net:  "unixgram",
	}

	// NOTIFY_SOCKET not set
	if socketAddr.Name == "" {
		return false, nil
	}

	if unsetEnvironment {
		err = os.Unsetenv("NOTIFY_SOCKET")
	}
	if err != nil {
		return false, err
	}

	conn, err := net.DialUnix(socketAddr.Net, nil, socketAddr)
	// Error connecting to NOTIFY_SOCKET
	if err != nil {
		return false, err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(state))
	// Error sending the message
	if err != nil {
		return false, err
	}
	return true, nil
}

func recycleIPTables(nw ip.IP4Net, lease *subnet.Lease) error {
	prevNetwork := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_NETWORK")
	prevSubnet := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_SUBNET")

	// recycle iptables rules only when network configured or subnet leased is not equal to current one.
	// 我觉得这里是或的关系，network不相等，删除旧的iptables。subnet不相等，删除旧的iptables
	if prevNetwork != nw && prevSubnet != lease.Subnet {
		log.Infof("Current network or subnet (%v, %v) is not equal to previous one (%v, %v), trying to recycle old iptables rules", nw, lease.Subnet, prevNetwork, prevSubnet)
		lease := &subnet.Lease{
			Subnet: prevSubnet,
		}
		if err := network.DeleteIPTables(network.MasqRules(prevNetwork, lease)); err != nil {
			return err
		}
	}
	return nil
}

/**
  优雅退出处理函数，如果收到信号os.Interrupt, syscall.SIGTERM。则执行cancel()函数
*/
func shutdownHandler(ctx context.Context, sigs chan os.Signal, cancel context.CancelFunc) {
	// Wait for the context do be Done or for the signal to come in to shutdown.
	select {
	case <-ctx.Done():
		log.Info("Stopping shutdownHandler...")
	case <-sigs:
		// Call cancel on the context to close everything down.
		cancel()
		log.Info("shutdownHandler sent cancel signal...")
	}

	// Unregister to get default OS nuke behaviour in case we don't exit cleanly
	signal.Stop(sigs)
}

/**
  从etcd里面获取prefix/config（例如：/kubernetes/network/config）的内容
  etcdctl --endpoints=https://xxxxxxxx:2379,https://xxxxxx:2379,https://xxxxxx:2379 --ca-file=/etc/kubernetes/cert/ca.pem
    --cert-file=/etc/flanneld/cert/flanneld.pem --key-file=/etc/flanneld/cert/flanneld-key.pem get /kubernetes/network/config

  结果：
    {"Network":"172.30.0.0/16", "SubnetLen": 21, "Backend": {"Type": "vxlan"}}
*/
func getConfig(ctx context.Context, sm subnet.Manager) (*subnet.Config, error) {
	// Retry every second until it succeeds
	for {
		config, err := sm.GetNetworkConfig(ctx)
		if err != nil {
			log.Errorf("Couldn't fetch network config: %s", err)
		} else if config == nil {
			log.Warningf("Couldn't find network config: %s", err)
		} else {
			log.Infof("Found network config - Backend type: %s", config.BackendType)
			return config, nil
		}
		select {
		case <-ctx.Done():
			return nil, errCanceled
		case <-time.After(1 * time.Second):
			fmt.Println("timed out")
		}
	}
}

/**
  监控subnet这个网段的节点, 主要用于subnet租约过期后, 能够快速获取新的租约
*/
func MonitorLease(ctx context.Context, sm subnet.Manager, bn backend.Network, wg *sync.WaitGroup) error {
	// Use the subnet manager to start watching leases.
	evts := make(chan subnet.Event)

	// waitGroup Add方法来设定应等待的线程的数量
	wg.Add(1)
	go func() {
		subnet.WatchLease(ctx, sm, bn.Lease().Subnet, evts)

		// 被等待的线程结束的时候，调用Done()
		wg.Done()
	}()

	// opts.subnetLeaseRenewMargin 默认值为60. 也就是说每隔60分钟续约一次, 在这里计算超时时间
	renewMargin := time.Duration(opts.subnetLeaseRenewMargin) * time.Minute
	dur := bn.Lease().Expiration.Sub(time.Now()) - renewMargin

	/**
	  死循环，每隔60分钟续约一次

	  两种情况下for循环会结束
	    1. 收到subnet.EventRemoved事件
	    2. Context.Done 上下文结束了
	  该函数退出，说明flanneld将要退出
	*/
	for {
		select {
		case <-time.After(dur):
			err := sm.RenewLease(ctx, bn.Lease())
			if err != nil {
				log.Error("Error renewing lease (trying again in 1 min): ", err)
				dur = time.Minute
				continue
			}

			log.Info("Lease renewed, new expiration: ", bn.Lease().Expiration)
			dur = bn.Lease().Expiration.Sub(time.Now()) - renewMargin

		case e := <-evts:
			switch e.Type {

			// 添加网络事件，就更新租约时间
			case subnet.EventAdded:
				bn.Lease().Expiration = e.Lease.Expiration
				dur = bn.Lease().Expiration.Sub(time.Now()) - renewMargin
				log.Infof("Waiting for %s to renew lease", dur)

			case subnet.EventRemoved:
				log.Error("Lease has been revoked. Shutting down daemon.")
				return errInterrupted
			}

		case <-ctx.Done():
			log.Infof("Stopped monitoring lease")
			return errCanceled
		}
	}
}

/**
  根据网卡名称或者IP找到对应的Interface信息
*/
func LookupExtIface(ifname string) (*backend.ExternalInterface, error) {
	var iface *net.Interface
	var ifaceAddr net.IP
	var err error

	/*
		如果ifname不为空的话
		  1、ifname为IP，通过IP找到对应的Interface信息，包括硬件地址，MTU等
		  2、ifname为网卡名称，通过网卡名称找到对应的Interface信息，包括硬件地址，MTU等
	*/
	if len(ifname) > 0 {
		if ifaceAddr = net.ParseIP(ifname); ifaceAddr != nil {
			log.Infof("Searching for interface using %s", ifaceAddr)
			iface, err = ip.GetInterfaceByIP(ifaceAddr)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		} else {
			iface, err = net.InterfaceByName(ifname)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		}
	} else {
		/**
		  否则从默认的网关接口里面找Interface信息
		*/
		log.Info("Determining IP address of default interface")
		if iface, err = ip.GetDefaultGatewayIface(); err != nil {
			return nil, fmt.Errorf("failed to get default interface: %s", err)
		}
	}

	/**
	  从Interface里面拿到IP地址
	*/
	if ifaceAddr == nil {
		ifaceAddr, err = ip.GetIfaceIP4Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv4 address for interface %s", iface.Name)
		}
	}

	log.Infof("Using interface with name %s and address %s", iface.Name, ifaceAddr)

	if iface.MTU == 0 {
		return nil, fmt.Errorf("failed to determine MTU for %s interface", ifaceAddr)
	}

	var extAddr net.IP

	/**
	  如果指定了publicIP，那么extAddr就是你指定的publicIP
	  否则，extAddr就是从刚刚获取到Interface里面的IP地址
	  这个publicIP在云主机场景还挺有用的，publicIP可以指定成你的云主机的公网IP。
	*/
	if len(opts.publicIP) > 0 {
		extAddr = net.ParseIP(opts.publicIP)
		if extAddr == nil {
			return nil, fmt.Errorf("invalid public IP address: %s", opts.publicIP)
		}
		log.Infof("Using %s as external address", extAddr)
	}

	if extAddr == nil {
		log.Infof("Defaulting external address to interface address (%s)", ifaceAddr)
		extAddr = ifaceAddr
	}

	return &backend.ExternalInterface{
		Iface:     iface,
		IfaceAddr: ifaceAddr,
		ExtAddr:   extAddr,
	}, nil
}

/**
  将网络信息写入到subnetFile里面
*/
func WriteSubnetFile(path string, nw ip.IP4Net, ipMasq bool, bn backend.Network) error {
	dir, name := filepath.Split(path)
	os.MkdirAll(dir, 0755)

	tempFile := filepath.Join(dir, "."+name)
	f, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	// Write out the first usable IP by incrementing
	// sn.IP by one
	sn := bn.Lease().Subnet
	sn.IP += 1

	fmt.Fprintf(f, "FLANNEL_NETWORK=%s\n", nw)
	fmt.Fprintf(f, "FLANNEL_SUBNET=%s\n", sn)
	fmt.Fprintf(f, "FLANNEL_MTU=%d\n", bn.MTU())
	_, err = fmt.Fprintf(f, "FLANNEL_IPMASQ=%v\n", ipMasq)
	f.Close()
	if err != nil {
		return err
	}

	// rename(2) the temporary file to the desired location so that it becomes
	// atomically visible with the contents
	return os.Rename(tempFile, path)
	//TODO - is this safe? What if it's not on the same FS?
}

/**
  提供一个rest api /healthz 做健康检查
    opts.healthzIP  默认值 "0.0.0.0"
    opts.healthzPort 默认值 0

  当opts.healthzPort为0的时候，不开启这个服务，所以是默认不开启健康检查服务的。
  如果你有需要，可以指定端口号开启服务来做健康检查
*/
func mustRunHealthz() {
	address := net.JoinHostPort(opts.healthzIP, strconv.Itoa(opts.healthzPort))
	log.Infof("Start healthz server on %s", address)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("flanneld is running"))
	})

	if err := http.ListenAndServe(address, nil); err != nil {
		log.Errorf("Start healthz server error. %v", err)
		panic(err)
	}
}

/**
  主要是下面两个用途，从subnet文件里面读取FLANNEL_SUBNET和FLANNEL_NETWORK
    ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_SUBNET")
    ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_NETWORK")

  默认的opts.subnetFile文件路径为:  /run/flannel/subnet.env

  示例内容如下
    FLANNEL_NETWORK=172.30.0.0/16
    FLANNEL_SUBNET=172.30.176.1/21
    FLANNEL_MTU=1450
    FLANNEL_IPMASQ=true
*/
func ReadCIDRFromSubnetFile(path string, CIDRKey string) ip.IP4Net {
	var prevCIDR ip.IP4Net
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		prevSubnetVals, err := godotenv.Read(path)
		if err != nil {
			log.Errorf("Couldn't fetch previous %s from subnet file at %s: %s", CIDRKey, path, err)
		} else if prevCIDRString, ok := prevSubnetVals[CIDRKey]; ok {
			err = prevCIDR.UnmarshalJSON([]byte(prevCIDRString))
			if err != nil {
				log.Errorf("Couldn't parse previous %s from subnet file at %s: %s", CIDRKey, path, err)
			}
		}
	}
	return prevCIDR
}
