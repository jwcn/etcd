// Copyright 2015 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package etcdmain

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/etcd/discovery"
	"github.com/coreos/etcd/embed"
	"github.com/coreos/etcd/etcdserver"
	"github.com/coreos/etcd/etcdserver/api/etcdhttp"
	"github.com/coreos/etcd/pkg/cors"
	"github.com/coreos/etcd/pkg/fileutil"
	pkgioutil "github.com/coreos/etcd/pkg/ioutil"
	"github.com/coreos/etcd/pkg/osutil"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/coreos/etcd/pkg/types"
	"github.com/coreos/etcd/proxy/httpproxy"
	"github.com/coreos/etcd/version"

	"github.com/coreos/pkg/capnslog"
	"google.golang.org/grpc"
)

type dirType string

var plog = capnslog.NewPackageLogger("github.com/coreos/etcd", "etcdmain")

var (
	dirMember = dirType("member")
	dirProxy  = dirType("proxy")
	dirEmpty  = dirType("empty")
)

func startEtcdOrProxyV2() {
	grpc.EnableTracing = false

	// 获取启动命令后的所有启动参数&映射
	cfg := newConfig()
	defaultInitialCluster := cfg.ec.InitialCluster

	// 解析启动时带的参数
	err := cfg.parse(os.Args[1:])
	if err != nil {
		plog.Errorf("error verifying flags, %v. See 'etcd --help'.", err)
		switch err {
		case embed.ErrUnsetAdvertiseClientURLsFlag:
			plog.Errorf("When listening on specific address(es), this etcd process must advertise accessible url(s) to each connected client.")
		}
		os.Exit(1)
	}
	// 初始化日志
	cfg.ec.SetupLogging()

	var stopped <-chan struct{}
	var errc <-chan error

	// Debug 输出项
	plog.Infof("etcd Version: %s\n", version.Version)
	plog.Infof("Git SHA: %s\n", version.GitSHA)
	plog.Infof("Go Version: %s\n", runtime.Version())
	plog.Infof("Go OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	GoMaxProcs := runtime.GOMAXPROCS(0)
	plog.Infof("setting maximum number of CPUs to %d, total number of available CPUs is %d", GoMaxProcs, runtime.NumCPU())

	// 更新集群通告URL默认主机，
	defaultHost, dhErr := (&cfg.ec).UpdateDefaultClusterFromName(defaultInitialCluster)
	if defaultHost != "" {
		plog.Infof("advertising using detected default host %q", defaultHost)
	}
	if dhErr != nil {
		plog.Noticef("failed to detect default host (%v)", dhErr)
	}

	if cfg.ec.Dir == "" {
		cfg.ec.Dir = fmt.Sprintf("%v.etcd", cfg.ec.Name)
		plog.Warningf("no data-dir provided, using default data-dir ./%s", cfg.ec.Dir)
	}

	// 解析 --data-dir 参数
	// 根据目录下文件名标识启动不同类型节点(非首次启动)
	// 意思可能是第一次启动本机的节点是啥类型, 以后还是啥类型
	which := identifyDataDirOrDie(cfg.ec.Dir)
	if which != dirEmpty {
		plog.Noticef("the server is already initialized as %v before, starting as etcd %v...", which, which)
		switch which {
		case dirMember:
			stopped, errc, err = startEtcd(&cfg.ec)
		case dirProxy:
			err = startProxy(cfg)
		default:
			plog.Panicf("unhandled dir type %v", which)
		}
	} else {
		// 首次启动节点, 没在目录下找到历史节点类型
		// 解析 --proxy=on
		// 对应启动本机为 member || proxy 类型节点
		shouldProxy := cfg.isProxy()
		if !shouldProxy {
			stopped, errc, err = startEtcd(&cfg.ec)
			if derr, ok := err.(*etcdserver.DiscoveryError); ok && derr.Err == discovery.ErrFullCluster {
				if cfg.shouldFallbackToProxy() {
					plog.Noticef("discovery cluster full, falling back to %s", fallbackFlagProxy)
					shouldProxy = true
				}
			}
		}
		if shouldProxy {
			err = startProxy(cfg)
		}
	}

	if err != nil {
		if derr, ok := err.(*etcdserver.DiscoveryError); ok {
			switch derr.Err {
			case discovery.ErrDuplicateID:
				plog.Errorf("member %q has previously registered with discovery service token (%s).", cfg.ec.Name, cfg.ec.Durl)
				plog.Errorf("But etcd could not find valid cluster configuration in the given data dir (%s).", cfg.ec.Dir)
				plog.Infof("Please check the given data dir path if the previous bootstrap succeeded")
				plog.Infof("or use a new discovery token if the previous bootstrap failed.")
			case discovery.ErrDuplicateName:
				plog.Errorf("member with duplicated name has registered with discovery service token(%s).", cfg.ec.Durl)
				plog.Errorf("please check (cURL) the discovery token for more information.")
				plog.Errorf("please do not reuse the discovery token and generate a new one to bootstrap the cluster.")
			default:
				plog.Errorf("%v", err)
				plog.Infof("discovery token %s was used, but failed to bootstrap the cluster.", cfg.ec.Durl)
				plog.Infof("please generate a new discovery token and try to bootstrap again.")
			}
			os.Exit(1)
		}

		if strings.Contains(err.Error(), "include") && strings.Contains(err.Error(), "--initial-cluster") {
			plog.Infof("%v", err)
			if cfg.ec.InitialCluster == cfg.ec.InitialClusterFromName(cfg.ec.Name) {
				plog.Infof("forgot to set --initial-cluster flag?")
			}
			if types.URLs(cfg.ec.APUrls).String() == embed.DefaultInitialAdvertisePeerURLs {
				plog.Infof("forgot to set --initial-advertise-peer-urls flag?")
			}
			if cfg.ec.InitialCluster == cfg.ec.InitialClusterFromName(cfg.ec.Name) && len(cfg.ec.Durl) == 0 {
				plog.Infof("if you want to use discovery service, please set --discovery flag.")
			}
			os.Exit(1)
		}
		plog.Fatalf("%v", err)
	}

	osutil.HandleInterrupts()

	// At this point, the initialization of etcd is done.
	// The listeners are listening on the TCP ports and ready
	// for accepting connections. The etcd instance should be
	// joined with the cluster and ready to serve incoming
	// connections.
	// 此时，etcd的初始化完成。
	// 侦听器正在侦听TCP端口并准备就绪
	// 开始接受连接。 etcd实例应该是与集群连接并准备投入服务连接。
	// 最后, 打印个 log 吧
	notifySystemd()

	select {
	case lerr := <-errc:
		// fatal out on listener errors
		plog.Fatal(lerr)
	case <-stopped:
	}

	osutil.Exit(0)
}

// startEtcd runs StartEtcd in addition to hooks needed for standalone etcd.
func startEtcd(cfg *embed.Config) (<-chan struct{}, <-chan error, error) {
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, nil, err
	}
	// 注册关闭函数到信号量协程里, 用于停止 ectd 后的一些善后工作
	osutil.RegisterInterruptHandler(e.Close)
	select {
	case <-e.Server.ReadyNotify(): // wait for e.Server to join the cluster
	case <-e.Server.StopNotify(): // publish aborted from 'ErrStopped'
	}
	return e.Server.StopNotify(), e.Err(), nil
}

// startProxy launches an HTTP proxy for client communication which proxies to other etcd nodes.
func startProxy(cfg *config) error {
	plog.Notice("proxy: this proxy supports v2 API only!")

	clientTLSInfo := cfg.ec.ClientTLSInfo
	if clientTLSInfo.Empty() {
		// Support old proxy behavior of defaulting to PeerTLSInfo
		// for both client and peer connections.
		clientTLSInfo = cfg.ec.PeerTLSInfo
	}
	clientTLSInfo.InsecureSkipVerify = cfg.ec.ClientAutoTLS
	cfg.ec.PeerTLSInfo.InsecureSkipVerify = cfg.ec.PeerAutoTLS

	pt, err := transport.NewTimeoutTransport(clientTLSInfo, time.Duration(cfg.cp.ProxyDialTimeoutMs)*time.Millisecond, time.Duration(cfg.cp.ProxyReadTimeoutMs)*time.Millisecond, time.Duration(cfg.cp.ProxyWriteTimeoutMs)*time.Millisecond)
	if err != nil {
		return err
	}
	pt.MaxIdleConnsPerHost = httpproxy.DefaultMaxIdleConnsPerHost

	if err = cfg.ec.PeerSelfCert(); err != nil {
		plog.Fatalf("could not get certs (%v)", err)
	}
	tr, err := transport.NewTimeoutTransport(cfg.ec.PeerTLSInfo, time.Duration(cfg.cp.ProxyDialTimeoutMs)*time.Millisecond, time.Duration(cfg.cp.ProxyReadTimeoutMs)*time.Millisecond, time.Duration(cfg.cp.ProxyWriteTimeoutMs)*time.Millisecond)
	if err != nil {
		return err
	}

	cfg.ec.Dir = filepath.Join(cfg.ec.Dir, "proxy")
	err = os.MkdirAll(cfg.ec.Dir, fileutil.PrivateDirMode)
	if err != nil {
		return err
	}

	var peerURLs []string
	clusterfile := filepath.Join(cfg.ec.Dir, "cluster")

	b, err := ioutil.ReadFile(clusterfile)
	switch {
	case err == nil:
		if cfg.ec.Durl != "" {
			plog.Warningf("discovery token ignored since the proxy has already been initialized. Valid cluster file found at %q", clusterfile)
		}
		if cfg.ec.DNSCluster != "" {
			plog.Warningf("DNS SRV discovery ignored since the proxy has already been initialized. Valid cluster file found at %q", clusterfile)
		}
		urls := struct{ PeerURLs []string }{}
		err = json.Unmarshal(b, &urls)
		if err != nil {
			return err
		}
		peerURLs = urls.PeerURLs
		plog.Infof("proxy: using peer urls %v from cluster file %q", peerURLs, clusterfile)
	case os.IsNotExist(err):
		var urlsmap types.URLsMap
		urlsmap, _, err = cfg.ec.PeerURLsMapAndToken("proxy")
		if err != nil {
			return fmt.Errorf("error setting up initial cluster: %v", err)
		}

		if cfg.ec.Durl != "" {
			var s string
			s, err = discovery.GetCluster(cfg.ec.Durl, cfg.ec.Dproxy)
			if err != nil {
				return err
			}
			if urlsmap, err = types.NewURLsMap(s); err != nil {
				return err
			}
		}
		peerURLs = urlsmap.URLs()
		plog.Infof("proxy: using peer urls %v ", peerURLs)
	default:
		return err
	}

	clientURLs := []string{}
	uf := func() []string {
		gcls, gerr := etcdserver.GetClusterFromRemotePeers(peerURLs, tr)

		if gerr != nil {
			plog.Warningf("proxy: %v", gerr)
			return []string{}
		}

		clientURLs = gcls.ClientURLs()

		urls := struct{ PeerURLs []string }{gcls.PeerURLs()}
		b, jerr := json.Marshal(urls)
		if jerr != nil {
			plog.Warningf("proxy: error on marshal peer urls %s", jerr)
			return clientURLs
		}

		err = pkgioutil.WriteAndSyncFile(clusterfile+".bak", b, 0600)
		if err != nil {
			plog.Warningf("proxy: error on writing urls %s", err)
			return clientURLs
		}
		err = os.Rename(clusterfile+".bak", clusterfile)
		if err != nil {
			plog.Warningf("proxy: error on updating clusterfile %s", err)
			return clientURLs
		}
		if !reflect.DeepEqual(gcls.PeerURLs(), peerURLs) {
			plog.Noticef("proxy: updated peer urls in cluster file from %v to %v", peerURLs, gcls.PeerURLs())
		}
		peerURLs = gcls.PeerURLs()

		return clientURLs
	}
	ph := httpproxy.NewHandler(pt, uf, time.Duration(cfg.cp.ProxyFailureWaitMs)*time.Millisecond, time.Duration(cfg.cp.ProxyRefreshIntervalMs)*time.Millisecond)
	ph = &cors.CORSHandler{
		Handler: ph,
		Info:    cfg.ec.CorsInfo,
	}

	if cfg.isReadonlyProxy() {
		ph = httpproxy.NewReadonlyHandler(ph)
	}

	// setup self signed certs when serving https
	cHosts, cTLS := []string{}, false
	for _, u := range cfg.ec.LCUrls {
		cHosts = append(cHosts, u.Host)
		cTLS = cTLS || u.Scheme == "https"
	}
	for _, u := range cfg.ec.ACUrls {
		cHosts = append(cHosts, u.Host)
		cTLS = cTLS || u.Scheme == "https"
	}
	listenerTLS := cfg.ec.ClientTLSInfo
	if cfg.ec.ClientAutoTLS && cTLS {
		listenerTLS, err = transport.SelfCert(filepath.Join(cfg.ec.Dir, "clientCerts"), cHosts)
		if err != nil {
			plog.Fatalf("proxy: could not initialize self-signed client certs (%v)", err)
		}
	}

	// Start a proxy server goroutine for each listen address
	for _, u := range cfg.ec.LCUrls {
		l, err := transport.NewListener(u.Host, u.Scheme, &listenerTLS)
		if err != nil {
			return err
		}

		host := u.String()
		go func() {
			plog.Info("proxy: listening for client requests on ", host)
			mux := http.NewServeMux()
			etcdhttp.HandlePrometheus(mux) // v2 proxy just uses the same port
			mux.Handle("/", ph)
			plog.Fatal(http.Serve(l, mux))
		}()
	}
	return nil
}

// identifyDataDirOrDie returns the type of the data dir.
// Dies if the datadir is invalid.
// 返回数据目录的类型。
// 遍历目录, 判断文件名
// 如果有文件名为 member, 则启动为 member 节点
// 有 proxy 则启动 HTTP proxy 代理节点
// 都不存在返回 empty
func identifyDataDirOrDie(dir string) dirType {
	names, err := fileutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return dirEmpty
		}
		plog.Fatalf("error listing data dir: %s", dir)
	}

	var m, p bool
	for _, name := range names {
		switch dirType(name) {
		case dirMember:
			m = true
		case dirProxy:
			p = true
		default:
			plog.Warningf("found invalid file/dir %s under data dir %s (Ignore this if you are upgrading etcd)", name, dir)
		}
	}

	if m && p {
		plog.Fatal("invalid datadir. Both member and proxy directories exist.")
	}
	if m {
		return dirMember
	}
	if p {
		return dirProxy
	}
	return dirEmpty
}

func checkSupportArch() {
	// TODO qualify arm64
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64le" {
		return
	}
	// unsupported arch only configured via environment variable
	// so unset here to not parse through flag
	defer os.Unsetenv("ETCD_UNSUPPORTED_ARCH")
	if env, ok := os.LookupEnv("ETCD_UNSUPPORTED_ARCH"); ok && env == runtime.GOARCH {
		plog.Warningf("running etcd on unsupported architecture %q since ETCD_UNSUPPORTED_ARCH is set", env)
		return
	}
	plog.Errorf("etcd on unsupported platform without ETCD_UNSUPPORTED_ARCH=%s set.", runtime.GOARCH)
	os.Exit(1)
}
