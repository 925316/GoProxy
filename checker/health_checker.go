package checker

import (
	"log"
	"time"

	"goproxy/config"
	"goproxy/pool"
	"goproxy/storage"
	"goproxy/validator"
)

// HealthChecker 健康检查器
type HealthChecker struct {
	storage   *storage.Storage
	validator *validator.Validator
	cfg       *config.Config
	poolMgr   *pool.Manager
}

func NewHealthChecker(s *storage.Storage, v *validator.Validator, cfg *config.Config, pm *pool.Manager) *HealthChecker {
	return &HealthChecker{
		storage:   s,
		validator: v,
		cfg:       cfg,
		poolMgr:   pm,
	}
}

// RunOnce 执行一次健康检查
func (hc *HealthChecker) RunOnce() {
	start := time.Now()
	log.Println("[health] 开始健康检查...")

	// 全量体检：S 级不再豁免——注入节点靠假低延迟拿 S 级后终身免检，
	// 证书检查才是判 S 的真标准
	proxies, err := hc.storage.GetBatchForHealthCheck(hc.cfg.HealthCheckBatchSize)
	if err != nil {
		log.Printf("[health] 获取检查批次失败: %v", err)
		return
	}

	if len(proxies) == 0 {
		log.Println("[health] 无需检查的代理")
		return
	}

	log.Printf("[health] 检查 %d 个代理", len(proxies))

	// 执行验证
	validCount := 0
	removeCount := 0
	updateCount := 0

	maxFail := hc.cfg.MaxFailCount
	if maxFail <= 0 {
		maxFail = 3
	}

	for result := range hc.validator.ValidateStream(proxies) {
		if result.Valid {
			validCount++
			// 更新延迟和质量等级
			latencyMs := int(result.Latency.Milliseconds())
			if err := hc.storage.UpdateExitInfo(result.Proxy.Address, result.ExitIP, result.ExitLocation, latencyMs); err == nil {
				updateCount++
			}
			// 通过即清零，fail_count 只增不减会把偶发失败的节点攒死
			if err := hc.storage.ResetFail(result.Proxy.Address); err != nil {
				log.Printf("[health] reset fail count error: %v", err)
			}
		} else {
			// 失败次数+1
			hc.storage.IncrementFailCount(result.Proxy.Address)
			// 如果失败次数 >= 阈值
			if result.Proxy.FailCount+1 >= maxFail {
				if result.Proxy.Source == "custom" {
					// 订阅代理：禁用而非删除
					hc.storage.DisableProxy(result.Proxy.Address)
				} else {
					hc.storage.Delete(result.Proxy.Address)
				}
				removeCount++
			}
		}
	}

	// 兜底清理攒满失败的免费节点（被 fail_count < 3 挡在体检批次外的）
	if purged, err := hc.storage.DeleteInvalid(maxFail); err == nil && purged > 0 {
		log.Printf("[health] 清理 fail_count>=%d 的免费节点: %d 个", maxFail, purged)
	}
	// 兜底把攒满失败的订阅节点置 disabled，交给探测唤醒恢复（H2 闭环）
	if disabled, err := hc.storage.DisableInvalidCustom(maxFail); err == nil && disabled > 0 {
		log.Printf("[health] 禁用 fail_count>=%d 的订阅节点: %d 个", maxFail, disabled)
	}

	elapsed := time.Since(start)
	log.Printf("[health] 完成: 验证%d 有效%d 更新%d 移除%d 耗时%v",
		len(proxies), validCount, updateCount, removeCount, elapsed)
}

// StartBackground 后台定时健康检查
func (hc *HealthChecker) StartBackground() {
	ticker := time.NewTicker(time.Duration(hc.cfg.HealthCheckInterval) * time.Minute)
	go func() {
		for range ticker.C {
			hc.RunOnce()
		}
	}()
	log.Printf("[health] 健康检查器已启动，间隔 %d 分钟", hc.cfg.HealthCheckInterval)
}
