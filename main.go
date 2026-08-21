package main

import (
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"goproxy/checker"
	"goproxy/config"
	"goproxy/custom"
	"goproxy/fetcher"
	"goproxy/logger"
	"goproxy/optimizer"
	"goproxy/pool"
	"goproxy/proxy"
	"goproxy/storage"
	"goproxy/validator"
	"goproxy/webui"
)

var fetchRunning atomic.Bool
var fetchMu sync.Mutex

func main() {
	// 初始化日志收集器
	logger.Init()

	// 加载配置
	cfg := config.Load()

	// 提示密码信息
	if os.Getenv("WEBUI_PASSWORD") == "" {
		log.Printf("[main] WebUI 使用默认密码: %s（可通过环境变量 WEBUI_PASSWORD 自定义）", config.DefaultPassword)
	} else {
		log.Println("[main] WebUI 密码已通过环境变量 WEBUI_PASSWORD 设置")
	}

	log.Printf("[main] 🎯 智能代理池配置: 容量=%d HTTP=%.0f%% SOCKS5=%.0f%% 延迟标准=%dms",
		cfg.PoolMaxSize, cfg.PoolHTTPRatio*100, (1-cfg.PoolHTTPRatio)*100, cfg.MaxLatencyMs)

	// 初始化存储
	store, err := storage.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("init storage: %v", err)
	}
	defer store.Close()

	// 初始化限流器
	fetcher.InitIPQueryLimiter(cfg.IPQueryRateLimit)

	// 初始化核心模块
	sourceMgr := fetcher.NewSourceManager(store.GetDB())
	fetch := fetcher.New(cfg.HTTPSourceURL, cfg.SOCKS5SourceURL, sourceMgr)
	validate := validator.New(cfg.ValidateConcurrency, cfg.ValidateTimeout, cfg.ValidateURL)
	poolMgr := pool.NewManager(store, cfg)
	healthChecker := checker.NewHealthChecker(store, validate, cfg, poolMgr)
	opt := optimizer.NewOptimizer(store, fetch, validate, poolMgr, cfg)
	
	// 清理无效代理（免费代理删除，订阅代理禁用）
	totalDeleted := 0
	if len(cfg.AllowedCountries) > 0 {
		if deleted, err := store.DeleteNotAllowedCountries(cfg.AllowedCountries); err == nil && deleted > 0 {
			log.Printf("[main] 🧹 已清理 %d 个非白名单免费代理 (允许: %v)", deleted, cfg.AllowedCountries)
			totalDeleted += int(deleted)
		}
		if disabled, err := store.DisableNotAllowedCountries(cfg.AllowedCountries); err == nil && disabled > 0 {
			log.Printf("[main] 🔒 已禁用 %d 个非白名单订阅代理", disabled)
		}
	} else if len(cfg.BlockedCountries) > 0 {
		if deleted, err := store.DeleteBlockedCountries(cfg.BlockedCountries); err == nil && deleted > 0 {
			log.Printf("[main] 🧹 已清理 %d 个屏蔽国家免费代理 (屏蔽: %v)", deleted, cfg.BlockedCountries)
			totalDeleted += int(deleted)
		}
		if disabled, err := store.DisableBlockedCountries(cfg.BlockedCountries); err == nil && disabled > 0 {
			log.Printf("[main] 🔒 已禁用 %d 个屏蔽国家订阅代理", disabled)
		}
	}
	if deleted, err := store.DeleteWithoutExitInfo(); err == nil && deleted > 0 {
		log.Printf("[main] 🧹 已清理 %d 个无出口信息的代理", deleted)
		totalDeleted += int(deleted)
	}
	
	// 创建 HTTP 代理服务器：随机轮换 + 最低延迟
	randomServer := proxy.New(store, cfg, "random", cfg.ProxyPort)
	stableServer := proxy.New(store, cfg, "lowest-latency", cfg.StableProxyPort)
	
	// 创建 SOCKS5 代理服务器：随机轮换 + 最低延迟
	socks5RandomServer := proxy.NewSOCKS5(store, cfg, "random", cfg.SOCKS5Port)
	socks5StableServer := proxy.NewSOCKS5(store, cfg, "lowest-latency", cfg.StableSOCKS5Port)

	// API 反向代理网关（429 智能检测核心）
	gatewayServer := proxy.NewGateway(store, cfg, cfg.GatewayPort)

	// 初始化订阅管理器
	customMgr := custom.NewManager(store, validate, cfg)

	// 配置变更通知 channel
	configChanged := make(chan struct{}, 1)

	// 启动 WebUI（传递池子管理器和订阅管理器）
	ui := webui.New(store, cfg, poolMgr, customMgr, func() {
		go smartFetchAndFill(fetch, validate, store, poolMgr)
	}, configChanged)
	ui.Start()

	// 首次智能填充（清理后立即触发）
	go func() {
		if totalDeleted > 0 {
			log.Printf("[main] 🚀 清理后立即启动补充填充...")
		} else {
			log.Println("[main] 🚀 启动初始化填充...")
		}
		smartFetchAndFill(fetch, validate, store, poolMgr)
	}()

	// 启动状态监控协程
	go startStatusMonitor(poolMgr, fetch, validate, store)

	// 启动健康检查器
	healthChecker.StartBackground()

	// 启动优化轮换器
	opt.StartBackground()

	// 启动订阅管理器
	go customMgr.Start()

	// 监听配置变更
	go watchConfigChanges(configChanged, poolMgr)

	// 启动 HTTP 稳定代理服务（最低延迟模式）
	go func() {
		if err := stableServer.Start(); err != nil {
			log.Fatalf("stable http proxy server: %v", err)
		}
	}()

	// 启动 API 反向代理网关（429 智能检测）
	startGateway(gatewayServer)

	// 启动 SOCKS5 稳定代理服务（最低延迟模式）
	go func() {
		if err := socks5StableServer.Start(); err != nil {
			log.Fatalf("stable socks5 proxy server: %v", err)
		}
	}()

	// 启动 SOCKS5 随机代理服务
	go func() {
		if err := socks5RandomServer.Start(); err != nil {
			log.Fatalf("random socks5 proxy server: %v", err)
		}
	}()

	// 启动 HTTP 随机代理服务（阻塞）
	if err := randomServer.Start(); err != nil {
		log.Fatalf("random http proxy server: %v", err)
	}
}

// startGateway 启动 API 反向代理网关（goroutine 包装）
func startGateway(g *proxy.Gateway) {
	go func() {
		if err := g.Start(); err != nil {
			log.Fatalf("[gateway] 网关启动失败: %v", err)
		}
	}()
}

// smartFetchAndFill 智能抓取和填充
func smartFetchAndFill(fetch *fetcher.Fetcher, validate *validator.Validator, store *storage.Storage, poolMgr *pool.Manager) {
	// 防止并发执行
	if !fetchRunning.CompareAndSwap(false, true) {
		log.Println("[main] 抓取已在运行，跳过")
		return
	}
	defer fetchRunning.Store(false)

	// 获取池子状态
	status, err := poolMgr.GetStatus()
	if err != nil {
		log.Printf("[main] 获取池子状态失败: %v", err)
		return
	}

	log.Printf("[main] 📊 池子状态: %s | HTTP=%d/%d SOCKS5=%d/%d 总计=%d/%d",
		status.State, status.HTTP, status.HTTPSlots, status.SOCKS5, status.SOCKS5Slots,
		status.Total, config.Get().PoolMaxSize)

	// 判断是否需要抓取
	needFetch, mode, preferredProtocol := poolMgr.NeedsFetch(status)
	if !needFetch {
		log.Println("[main] 池子健康，无需抓取")
		return
	}

	log.Printf("[main] 🔍 智能抓取: 模式=%s 协议偏好=%s", mode, preferredProtocol)

	// 智能抓取
	candidates, err := fetch.FetchSmart(mode, preferredProtocol)
	if err != nil {
		log.Printf("[main] 抓取失败: %v", err)
		return
	}

	// 按协议分组
	var httpCandidates, socks5Candidates []storage.Proxy
	for _, c := range candidates {
		if c.Protocol == "http" {
			httpCandidates = append(httpCandidates, c)
		} else {
			socks5Candidates = append(socks5Candidates, c)
		}
	}

	log.Printf("[main] 抓取到 %d 个候选代理（SOCKS5=%d HTTP=%d），按协议并发验证...",
		len(candidates), len(socks5Candidates), len(httpCandidates))

	// 共享计数器
	var addedCount atomic.Int32
	var validCount atomic.Int32
	var rejectedNoExit atomic.Int32
	var rejectedLatency atomic.Int32
	var rejectedGeo atomic.Int32
	var rejectedFull atomic.Int32

	// 入池处理函数（两个协程共用）
	processResult := func(result validator.Result) {
		if !result.Valid {
			return
		}

		validCount.Add(1)
		latencyMs := int(result.Latency.Milliseconds())

		cfg := config.Get()
		maxLatency := cfg.GetLatencyThreshold(status.State)

		if result.ExitIP == "" || result.ExitLocation == "" {
			rejectedNoExit.Add(1)
			return
		}

		if latencyMs > maxLatency {
			rejectedLatency.Add(1)
			return
		}

		proxyToAdd := storage.Proxy{
			Address:      result.Proxy.Address,
			Protocol:     result.Proxy.Protocol,
			ExitIP:       result.ExitIP,
			ExitLocation: result.ExitLocation,
			Latency:      latencyMs,
		}

		if added, reason := poolMgr.TryAddProxy(proxyToAdd); added {
			addedCount.Add(1)
		} else if reason == "slots_full" {
			rejectedFull.Add(1)
		} else if len(result.ExitLocation) >= 2 {
			countryCode := result.ExitLocation[:2]
			for _, blocked := range cfg.BlockedCountries {
				if countryCode == blocked {
					rejectedGeo.Add(1)
					break
				}
			}
		}
	}

	// 池子是否已满的检查函数
	poolFilled := func() bool {
		currentStatus, _ := poolMgr.GetStatus()
		return !poolMgr.NeedsFetchQuick(currentStatus)
	}

	var wg sync.WaitGroup

	// SOCKS5 协程：验证快，优先填充
	if len(socks5Candidates) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			count := 0
			for result := range validate.ValidateStream(socks5Candidates) {
				processResult(result)
				count++
				if count%20 == 0 && poolFilled() {
					log.Println("[main] ✅ SOCKS5 验证中检测到池子已满，停止")
					break
				}
			}
			log.Printf("[main] SOCKS5 验证完成，处理 %d 个", count)
		}()
	}

	// HTTP 协程：有额外 HTTPS 检测，较慢
	if len(httpCandidates) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			count := 0
			for result := range validate.ValidateStream(httpCandidates) {
				processResult(result)
				count++
				if count%20 == 0 && poolFilled() {
					log.Println("[main] ✅ HTTP 验证中检测到池子已满，停止")
					break
				}
			}
			log.Printf("[main] HTTP 验证完成，处理 %d 个", count)
		}()
	}

	wg.Wait()

	// 最终状态
	finalStatus, _ := poolMgr.GetStatus()
	log.Printf("[main] 填充完成: 验证%d 通过%d 入池%d | 拒绝[无出口:%d 延迟:%d 地理:%d 满:%d] | 最终: %s HTTP=%d SOCKS5=%d",
		len(candidates), validCount.Load(), addedCount.Load(),
		rejectedNoExit.Load(), rejectedLatency.Load(), rejectedGeo.Load(), rejectedFull.Load(),
		finalStatus.State, finalStatus.HTTP, finalStatus.SOCKS5)
}

// startStatusMonitor 状态监控协程
func startStatusMonitor(poolMgr *pool.Manager, fetch *fetcher.Fetcher, validate *validator.Validator, store *storage.Storage) {
	ticker := time.NewTicker(30 * time.Second)
	log.Println("[monitor] 📡 状态监控器已启动（每30秒检查）")

	for range ticker.C {
		status, err := poolMgr.GetStatus()
		if err != nil {
			continue
		}

		// 每分钟检查池子状态
		needFetch, mode, preferredProtocol := poolMgr.NeedsFetch(status)
		if needFetch {
			log.Printf("[monitor] ⚠️  检测到池子需求: 状态=%s 模式=%s 协议=%s",
				status.State, mode, preferredProtocol)
			// 触发智能填充
			go smartFetchAndFill(fetch, validate, store, poolMgr)
		}
	}
}

// watchConfigChanges 监听配置变更
func watchConfigChanges(configChanged <-chan struct{}, poolMgr *pool.Manager) {
	var oldSize int
	var oldRatio float64

	cfg := config.Get()
	oldSize = cfg.PoolMaxSize
	oldRatio = cfg.PoolHTTPRatio

	for range configChanged {
		newCfg := config.Get()
		if newCfg.PoolMaxSize != oldSize || newCfg.PoolHTTPRatio != oldRatio {
			log.Printf("[config] 🔧 配置变更检测: 容量 %d→%d 比例 %.2f→%.2f",
				oldSize, newCfg.PoolMaxSize, oldRatio, newCfg.PoolHTTPRatio)
			poolMgr.AdjustForConfigChange(oldSize, oldRatio)
			oldSize = newCfg.PoolMaxSize
			oldRatio = newCfg.PoolHTTPRatio
		}
	}
}
