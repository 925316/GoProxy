package storage

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Proxy struct {
	ID           int64     `json:"id"`
	Address      string    `json:"address"`
	Protocol     string    `json:"protocol"`
	ExitIP       string    `json:"exit_ip"`
	ExitLocation string    `json:"exit_location"`
	Latency      int       `json:"latency"`
	QualityGrade string    `json:"quality_grade"`
	UseCount     int       `json:"use_count"`
	SuccessCount int       `json:"success_count"`
	FailCount    int       `json:"fail_count"`
	LastUsed     time.Time `json:"last_used"`
	LastCheck    time.Time `json:"last_check"`
	CreatedAt    time.Time `json:"created_at"`
	Status         string    `json:"status"`
	Source         string    `json:"source"`          // "free" 或 "custom"
	SubscriptionID int64    `json:"subscription_id"` // 所属订阅ID（0=免费代理）
	CooldownUntil  time.Time `json:"cooldown_until"` // 429/限流冷却截止时间（零值=不在冷却中）
	EofCount       int       `json:"eof_count"`      // 流式响应中途 EOF 计数（达阈值触发冷却）
}

// Subscription 订阅信息
type Subscription struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	FilePath    string    `json:"file_path"`
	Format      string    `json:"format"` // clash / plain / base64 / auto
	RefreshMin  int       `json:"refresh_min"`
	LastFetch   time.Time `json:"last_fetch"`
	LastSuccess time.Time `json:"last_success"` // 最后一次有可用节点的时间
	Status      string    `json:"status"`       // active / paused
	ProxyCount  int       `json:"proxy_count"`
	CreatedAt   time.Time `json:"created_at"`
	Contributed bool      `json:"contributed"` // 是否为访客贡献
}

// SourceStatus 代理源状态
type SourceStatus struct {
	ID               int64
	URL              string
	SuccessCount     int
	FailCount        int
	ConsecutiveFails int
	LastSuccess      time.Time
	LastFail         time.Time
	Status           string    // active/degraded/disabled
	DisabledUntil    time.Time
}

type Storage struct {
	db *sql.DB
}

func New(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite 单写

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Storage) initSchema() error {
	// 创建代理表
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS proxies (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			address        TEXT NOT NULL UNIQUE,
			protocol       TEXT NOT NULL,
			exit_ip        TEXT NOT NULL DEFAULT '',
			exit_location  TEXT NOT NULL DEFAULT '',
			latency        INTEGER NOT NULL DEFAULT 0,
			quality_grade  TEXT NOT NULL DEFAULT 'C',
			use_count      INTEGER NOT NULL DEFAULT 0,
			success_count  INTEGER NOT NULL DEFAULT 0,
			fail_count     INTEGER NOT NULL DEFAULT 0,
			last_used      DATETIME,
			last_check     DATETIME,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			status         TEXT NOT NULL DEFAULT 'active'
		)
	`)
	if err != nil {
		return err
	}

	// 创建索引
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_protocol_latency ON proxies(protocol, latency)`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_quality_grade ON proxies(quality_grade, latency)`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_status ON proxies(status)`)

	// 创建源状态表
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS source_status (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			url               TEXT NOT NULL UNIQUE,
			success_count     INTEGER NOT NULL DEFAULT 0,
			fail_count        INTEGER NOT NULL DEFAULT 0,
			consecutive_fails INTEGER NOT NULL DEFAULT 0,
			last_success      DATETIME,
			last_fail         DATETIME,
			status            TEXT NOT NULL DEFAULT 'active',
			disabled_until    DATETIME
		)
	`)
	if err != nil {
		return err
	}

	// 迁移：处理旧的 location 字段（如果存在）
	var hasOldLocation int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='location'`).Scan(&hasOldLocation)
	if err == nil && hasOldLocation > 0 {
		log.Println("[storage] migrating: renaming location to exit_location")
		// 如果有旧的 location 字段，先添加新字段再复制数据
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN exit_location TEXT NOT NULL DEFAULT ''`)
		s.db.Exec(`UPDATE proxies SET exit_location = location WHERE location != ''`)
	}

	// 迁移：添加 exit_ip 字段
	var hasExitIP int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='exit_ip'`).Scan(&hasExitIP)
	if err == nil && hasExitIP == 0 {
		log.Println("[storage] migrating: adding exit_ip column")
		_, err = s.db.Exec(`ALTER TABLE proxies ADD COLUMN exit_ip TEXT NOT NULL DEFAULT ''`)
		if err != nil {
			return fmt.Errorf("migrate exit_ip column: %w", err)
		}
	}

	// 迁移：添加 exit_location 字段
	var hasExitLocation int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='exit_location'`).Scan(&hasExitLocation)
	if err == nil && hasExitLocation == 0 {
		log.Println("[storage] migrating: adding exit_location column")
		_, err = s.db.Exec(`ALTER TABLE proxies ADD COLUMN exit_location TEXT NOT NULL DEFAULT ''`)
		if err != nil {
			return fmt.Errorf("migrate exit_location column: %w", err)
		}
	}

	// 迁移：添加 latency 字段
	var hasLatency int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='latency'`).Scan(&hasLatency)
	if err == nil && hasLatency == 0 {
		log.Println("[storage] migrating: adding latency column")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN latency INTEGER NOT NULL DEFAULT 0`)
	}

	// 迁移：添加质量等级字段
	var hasQuality int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='quality_grade'`).Scan(&hasQuality)
	if hasQuality == 0 {
		log.Println("[storage] migrating: adding quality_grade column")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN quality_grade TEXT NOT NULL DEFAULT 'C'`)
	}

	// 迁移：添加使用统计字段
	var hasUseCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='use_count'`).Scan(&hasUseCount)
	if hasUseCount == 0 {
		log.Println("[storage] migrating: adding usage tracking columns")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0`)
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN success_count INTEGER NOT NULL DEFAULT 0`)
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN last_used DATETIME`)
	}

	// 迁移：添加状态字段
	var hasStatus int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='status'`).Scan(&hasStatus)
	if hasStatus == 0 {
		log.Println("[storage] migrating: adding status column")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`)
	}

	// 迁移：添加 source 字段（区分免费代理和订阅代理）
	var hasSource int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='source'`).Scan(&hasSource)
	if hasSource == 0 {
		log.Println("[storage] migrating: adding source column")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN source TEXT NOT NULL DEFAULT 'free'`)
	}
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_source ON proxies(source, status)`)

	// 迁移：添加 subscription_id 字段
	var hasSubID int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='subscription_id'`).Scan(&hasSubID)
	if hasSubID == 0 {
		log.Println("[storage] migrating: adding subscription_id column")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN subscription_id INTEGER NOT NULL DEFAULT 0`)
	}

	// 迁移：添加 cooldown_until 字段（429/限流冷却，NULL=不在冷却中）
	var hasCooldown int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='cooldown_until'`).Scan(&hasCooldown)
	if hasCooldown == 0 {
		log.Println("[storage] 迁移: 添加 cooldown_until 列")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN cooldown_until DATETIME`)
	}
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_cooldown_until ON proxies(cooldown_until)`)

	// 迁移：添加 eof_count 字段（流式响应中途 EOF 计数，达阈值触发 24h 冷却）
	var hasEofCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name='eof_count'`).Scan(&hasEofCount)
	if hasEofCount == 0 {
		log.Println("[storage] 迁移: 添加 eof_count 列")
		s.db.Exec(`ALTER TABLE proxies ADD COLUMN eof_count INTEGER NOT NULL DEFAULT 0`)
	}

	// 创建订阅表
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS subscriptions (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			name          TEXT NOT NULL DEFAULT '',
			url           TEXT NOT NULL DEFAULT '',
			file_path     TEXT NOT NULL DEFAULT '',
			format        TEXT NOT NULL DEFAULT 'clash',
			refresh_min   INTEGER NOT NULL DEFAULT 60,
			last_fetch    DATETIME,
			status        TEXT NOT NULL DEFAULT 'active',
			proxy_count   INTEGER NOT NULL DEFAULT 0,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// 迁移：订阅表添加 contributed 和 last_success 字段
	var hasContributed int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('subscriptions') WHERE name='contributed'`).Scan(&hasContributed)
	if hasContributed == 0 {
		s.db.Exec(`ALTER TABLE subscriptions ADD COLUMN contributed INTEGER NOT NULL DEFAULT 0`)
	}
	var hasLastSuccess int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('subscriptions') WHERE name='last_success'`).Scan(&hasLastSuccess)
	if hasLastSuccess == 0 {
		s.db.Exec(`ALTER TABLE subscriptions ADD COLUMN last_success DATETIME`)
	}

	return nil
}

// AddProxy 新增免费代理，已存在则忽略
func (s *Storage) AddProxy(address, protocol string) error {
	result, err := s.db.Exec(
		`INSERT OR IGNORE INTO proxies (address, protocol, source) VALUES (?, ?, 'free')`,
		address, protocol,
	)
	if err != nil {
		log.Printf("[storage] AddProxy %s error: %v", address, err)
		return err
	}
	
	// 检查是否真的插入了
	affected, _ := result.RowsAffected()
	if affected == 0 {
		log.Printf("[storage] AddProxy %s ignored (already exists or constraint)", address)
	}
	return nil
}

// AddProxies 批量新增
func (s *Storage) AddProxies(proxies []Proxy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO proxies (address, protocol) VALUES (?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, p := range proxies {
		if _, err := stmt.Exec(p.Address, p.Protocol); err != nil {
			log.Printf("insert proxy %s error: %v", p.Address, err)
		}
	}
	return tx.Commit()
}

// GetRandom 随机取一个可用代理（优先选择质量高的，排除冷却中）
func (s *Storage) GetRandom() (*Proxy, error) {
	rows, err := s.db.Query(
		`SELECT `+proxyColumns+`
		 FROM proxies
		 WHERE status = 'active' AND fail_count < 3
		   AND (cooldown_until IS NULL OR cooldown_until <= CURRENT_TIMESTAMP)
		 ORDER BY
		   CASE quality_grade
		     WHEN 'S' THEN 1
		     WHEN 'A' THEN 2
		     WHEN 'B' THEN 3
		     ELSE 4
		   END,
		   RANDOM()
		 LIMIT 1`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		return scanProxy(rows)
	}
	return nil, fmt.Errorf("no available proxy")
}

// proxyColumns 代理表查询的标准列列表
const proxyColumns = `id, address, protocol, exit_ip, exit_location, latency, quality_grade,
	use_count, success_count, fail_count, last_used, last_check, created_at, status, source, subscription_id, cooldown_until, eof_count`

// scanProxy 扫描代理行数据
func scanProxy(rows *sql.Rows) (*Proxy, error) {
	p := &Proxy{}
	var lastUsed, lastCheck, cooldownUntil sql.NullTime
	var source sql.NullString
	var subID sql.NullInt64
	if err := rows.Scan(&p.ID, &p.Address, &p.Protocol, &p.ExitIP, &p.ExitLocation,
		&p.Latency, &p.QualityGrade, &p.UseCount, &p.SuccessCount, &p.FailCount,
		&lastUsed, &lastCheck, &p.CreatedAt, &p.Status, &source, &subID, &cooldownUntil, &p.EofCount); err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		p.LastUsed = lastUsed.Time
	}
	if lastCheck.Valid {
		p.LastCheck = lastCheck.Time
	}
	if cooldownUntil.Valid {
		p.CooldownUntil = cooldownUntil.Time
	}
	if source.Valid {
		p.Source = source.String
	} else {
		p.Source = "free"
	}
	if subID.Valid {
		p.SubscriptionID = subID.Int64
	}
	return p, nil
}

// GetAll 获取所有可用代理
func (s *Storage) GetAll() ([]Proxy, error) {
	return s.GetAllFiltered("")
}

// GetAllFiltered 获取可用代理（可按来源过滤，自动排除冷却中的节点）
// sourceFilter: "" = 全部, "free" = 仅免费, "custom" = 仅订阅
func (s *Storage) GetAllFiltered(sourceFilter string) ([]Proxy, error) {
	query := `SELECT ` + proxyColumns + `
		 FROM proxies
		 WHERE status IN ('active', 'degraded') AND fail_count < 3
		   AND (cooldown_until IS NULL OR cooldown_until <= CURRENT_TIMESTAMP)`
	var args []interface{}
	if sourceFilter != "" {
		query += ` AND source = ?`
		args = append(args, sourceFilter)
	}
	query += ` ORDER BY latency ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, nil
}

// SetCooldown 将节点加入冷却区（429/上游限流/EOF 超阈值），duration 秒后自动回池
// 同时清零 eof_count：冷却结束后重新计数，避免历史 EOF 永久累积
func (s *Storage) SetCooldown(address string, duration time.Duration) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET cooldown_until = datetime('now', ?), eof_count = 0 WHERE address = ?`,
		fmt.Sprintf("+%d seconds", int(duration.Seconds())), address,
	)
	if err != nil {
		log.Printf("[storage] SetCooldown %s 出错: %v", address, err)
	}
	return err
}

// RecordEof 记录一次流式响应中途 EOF，返回累计后的 eof_count
func (s *Storage) RecordEof(address string) (int, error) {
	_, err := s.db.Exec(
		`UPDATE proxies SET eof_count = eof_count + 1 WHERE address = ?`,
		address,
	)
	if err != nil {
		log.Printf("[storage] RecordEof %s 出错: %v", address, err)
		return 0, err
	}
	var count int
	if err := s.db.QueryRow(`SELECT eof_count FROM proxies WHERE address = ?`, address).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// ClearCooldown 立即解除节点冷却
func (s *Storage) ClearCooldown(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET cooldown_until = NULL WHERE address = ?`,
		address,
	)
	return err
}

// GetCooldownProxies 获取所有处于冷却中的代理
func (s *Storage) GetCooldownProxies() ([]Proxy, error) {
	rows, err := s.db.Query(
		`SELECT `+proxyColumns+`
		 FROM proxies
		 WHERE cooldown_until IS NOT NULL AND cooldown_until > CURRENT_TIMESTAMP
		 ORDER BY cooldown_until ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, nil
}

// GetRandomExclude 排除指定地址随机取一个
func (s *Storage) GetRandomExclude(excludes []string) (*Proxy, error) {
	return s.GetRandomExcludeFiltered(excludes, "")
}

// GetRandomExcludeFiltered 排除指定地址随机取一个（可按来源过滤）
func (s *Storage) GetRandomExcludeFiltered(excludes []string, sourceFilter string) (*Proxy, error) {
	proxies, err := s.GetAllFiltered(sourceFilter)
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool)
	for _, e := range excludes {
		excludeMap[e] = true
	}

	var available []Proxy
	for _, p := range proxies {
		if !excludeMap[p.Address] {
			available = append(available, p)
		}
	}

	if len(available) == 0 {
		if sourceFilter != "" {
			return nil, fmt.Errorf("no available %s proxy", sourceFilter)
		}
		return s.GetRandom()
	}

	p := available[rand.Intn(len(available))]
	return &p, nil
}

// GetLowestLatencyExclude 排除指定地址后获取延迟最低的代理
func (s *Storage) GetLowestLatencyExclude(excludes []string) (*Proxy, error) {
	return s.GetLowestLatencyExcludeFiltered(excludes, "")
}

// GetLowestLatencyExcludeFiltered 排除指定地址后获取延迟最低的代理（可按来源过滤）
func (s *Storage) GetLowestLatencyExcludeFiltered(excludes []string, sourceFilter string) (*Proxy, error) {
	proxies, err := s.GetAllFiltered(sourceFilter)
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool)
	for _, e := range excludes {
		excludeMap[e] = true
	}

	for _, p := range proxies {
		if !excludeMap[p.Address] {
			proxy := p
			return &proxy, nil
		}
	}

	return nil, fmt.Errorf("no available proxy")
}

// GetRandomByProtocolExclude 按协议获取随机代理（排除已尝试的）
func (s *Storage) GetRandomByProtocolExclude(protocol string, excludes []string) (*Proxy, error) {
	return s.GetRandomByProtocolExcludeFiltered(protocol, excludes, "")
}

// GetRandomByProtocolExcludeFiltered 按协议获取随机代理（可按来源过滤）
func (s *Storage) GetRandomByProtocolExcludeFiltered(protocol string, excludes []string, sourceFilter string) (*Proxy, error) {
	proxies, err := s.GetAllFiltered(sourceFilter)
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool)
	for _, e := range excludes {
		excludeMap[e] = true
	}

	var available []Proxy
	for _, p := range proxies {
		if p.Protocol == protocol && !excludeMap[p.Address] {
			available = append(available, p)
		}
	}

	if len(available) == 0 {
		return nil, fmt.Errorf("no %s proxy available", protocol)
	}

	proxy := available[time.Now().UnixNano()%int64(len(available))]
	return &proxy, nil
}

// GetLowestLatencyByProtocolExclude 按协议获取最低延迟代理（排除已尝试的）
func (s *Storage) GetLowestLatencyByProtocolExclude(protocol string, excludes []string) (*Proxy, error) {
	return s.GetLowestLatencyByProtocolExcludeFiltered(protocol, excludes, "")
}

// GetLowestLatencyByProtocolExcludeFiltered 按协议获取最低延迟代理（可按来源过滤）
func (s *Storage) GetLowestLatencyByProtocolExcludeFiltered(protocol string, excludes []string, sourceFilter string) (*Proxy, error) {
	proxies, err := s.GetAllFiltered(sourceFilter)
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool)
	for _, e := range excludes {
		excludeMap[e] = true
	}

	for _, p := range proxies {
		if p.Protocol == protocol && !excludeMap[p.Address] {
			proxy := p
			return &proxy, nil
		}
	}

	return nil, fmt.Errorf("no %s proxy available", protocol)
}

// Delete 立即删除指定代理
func (s *Storage) Delete(address string) error {
	_, err := s.db.Exec(`DELETE FROM proxies WHERE address = ?`, address)
	return err
}

// IncrFail 增加失败次数
func (s *Storage) IncrFail(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET fail_count = fail_count + 1, last_check = CURRENT_TIMESTAMP WHERE address = ?`,
		address,
	)
	return err
}

// ResetFail 重置失败次数（验证通过）
func (s *Storage) ResetFail(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET fail_count = 0, last_check = CURRENT_TIMESTAMP WHERE address = ?`,
		address,
	)
	return err
}

// UpdateLatency 更新代理的延迟信息（毫秒）
func (s *Storage) UpdateLatency(address string, latencyMs int) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET latency = ? WHERE address = ?`,
		latencyMs, address,
	)
	return err
}

// UpdateExitInfo 更新代理的出口 IP、位置和质量等级
func (s *Storage) UpdateExitInfo(address, exitIP, exitLocation string, latencyMs int) error {
	grade := CalculateQualityGrade(latencyMs)
	_, err := s.db.Exec(
		`UPDATE proxies SET exit_ip = ?, exit_location = ?, latency = ?, quality_grade = ? WHERE address = ?`,
		exitIP, exitLocation, latencyMs, grade, address,
	)
	return err
}

// RecordProxyUse 记录代理使用（成功）
func (s *Storage) RecordProxyUse(address string, success bool) error {
	if success {
		_, err := s.db.Exec(
			`UPDATE proxies SET use_count = use_count + 1, success_count = success_count + 1, 
			 last_used = CURRENT_TIMESTAMP WHERE address = ?`,
			address,
		)
		return err
	}
	_, err := s.db.Exec(
		`UPDATE proxies SET use_count = use_count + 1, fail_count = fail_count + 1, 
		 last_used = CURRENT_TIMESTAMP WHERE address = ?`,
		address,
	)
	return err
}

// GetWorstProxies 获取指定协议中延迟最高的N个代理（仅免费代理）
func (s *Storage) GetWorstProxies(protocol string, limit int) ([]Proxy, error) {
	rows, err := s.db.Query(
		`SELECT `+proxyColumns+`
		 FROM proxies
		 WHERE protocol = ? AND status = 'active' AND source = 'free'
		   AND quality_grade != 'S'
		   AND (JULIANDAY('now') - JULIANDAY(created_at)) * 1440 > 60
		 ORDER BY latency DESC, fail_count DESC
		 LIMIT ?`, protocol, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, nil
}

// ReplaceProxy 替换代理（删除旧的，添加新的）
func (s *Storage) ReplaceProxy(oldAddress string, newProxy Proxy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 删除旧代理
	_, err = tx.Exec(`DELETE FROM proxies WHERE address = ?`, oldAddress)
	if err != nil {
		return err
	}

	// 添加新代理（带完整信息）
	grade := CalculateQualityGrade(newProxy.Latency)
	source := newProxy.Source
	if source == "" {
		source = "free"
	}
	_, err = tx.Exec(
		`INSERT INTO proxies (address, protocol, exit_ip, exit_location, latency, quality_grade, status, source)
		 VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
		newProxy.Address, newProxy.Protocol, newProxy.ExitIP, newProxy.ExitLocation, newProxy.Latency, grade, source,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// MarkAsReplacementCandidate 标记代理为替换候选
func (s *Storage) MarkAsReplacementCandidate(addresses []string) error {
	if len(addresses) == 0 {
		return nil
	}
	placeholders := make([]string, len(addresses))
	args := make([]interface{}, len(addresses))
	for i, addr := range addresses {
		placeholders[i] = "?"
		args[i] = addr
	}
	query := fmt.Sprintf(`UPDATE proxies SET status = 'candidate_replace' WHERE address IN (%s)`,
		fmt.Sprintf("%s", placeholders))
	_, err := s.db.Exec(query, args...)
	return err
}

// GetAverageLatency 获取指定协议的平均延迟
func (s *Storage) GetAverageLatency(protocol string) (int, error) {
	var avg sql.NullFloat64
	err := s.db.QueryRow(
		`SELECT AVG(latency) FROM proxies WHERE protocol = ? AND status = 'active' AND latency > 0`,
		protocol,
	).Scan(&avg)
	if err != nil || !avg.Valid {
		return 0, err
	}
	return int(avg.Float64), nil
}

// GetQualityDistribution 获取质量分布统计
func (s *Storage) GetQualityDistribution() (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT quality_grade, COUNT(*) as count 
		 FROM proxies 
		 WHERE status = 'active' AND fail_count < 3
		 GROUP BY quality_grade`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dist := make(map[string]int)
	for rows.Next() {
		var grade string
		var count int
		if err := rows.Scan(&grade, &count); err != nil {
			return nil, err
		}
		dist[grade] = count
	}
	return dist, nil
}

// GetBatchForHealthCheck 获取一批需要健康检查的代理（排除冷却中的）
func (s *Storage) GetBatchForHealthCheck(batchSize int, skipSGrade bool) ([]Proxy, error) {
	query := `SELECT ` + proxyColumns + `
		 FROM proxies
		 WHERE status IN ('active', 'degraded') AND fail_count < 3
		   AND (cooldown_until IS NULL OR cooldown_until <= CURRENT_TIMESTAMP)`

	if skipSGrade {
		query += ` AND quality_grade != 'S'`
	}

	query += ` ORDER BY 
		COALESCE(last_check, '1970-01-01') ASC,
		quality_grade DESC
		LIMIT ?`

	rows, err := s.db.Query(query, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, nil
}

// CalculateQualityGrade 根据延迟计算质量等级
func CalculateQualityGrade(latencyMs int) string {
	switch {
	case latencyMs <= 500:
		return "S" // 超快
	case latencyMs <= 1000:
		return "A" // 良好
	case latencyMs <= 2000:
		return "B" // 可用
	default:
		return "C" // 淘汰候选
	}
}

// DeleteInvalid 删除失败次数超过阈值的代理（仅免费代理）
func (s *Storage) DeleteInvalid(maxFailCount int) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE fail_count >= ? AND source = 'free'`, maxFailCount)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteBlockedCountries 删除指定国家代码出口的代理
func (s *Storage) DeleteBlockedCountries(countryCodes []string) (int64, error) {
	if len(countryCodes) == 0 {
		return 0, nil
	}

	var totalDeleted int64
	for _, code := range countryCodes {
		// exit_location 格式：如 "CN Beijing" 或 "CN"（仅国家代码）
		// 同时匹配 "CODE" 和 "CODE ..." 两种情况（仅删除免费代理）
		res, err := s.db.Exec(`DELETE FROM proxies WHERE source = 'free' AND (exit_location = ? OR exit_location LIKE ?)`, code, code+" %")
		if err != nil {
			return totalDeleted, err
		}
		affected, _ := res.RowsAffected()
		totalDeleted += affected
	}
	return totalDeleted, nil
}

// DeleteNotAllowedCountries 删除不在白名单中的代理
func (s *Storage) DeleteNotAllowedCountries(allowedCodes []string) (int64, error) {
	if len(allowedCodes) == 0 {
		return 0, nil
	}

	// 构建 WHERE 条件：exit_location 不以任何白名单国家代码开头
	// 即：NOT (exit_location = 'US' OR exit_location LIKE 'US %' OR ...)
	conditions := make([]string, 0, len(allowedCodes)*2)
	args := make([]interface{}, 0, len(allowedCodes)*2)
	for _, code := range allowedCodes {
		conditions = append(conditions, "exit_location = ?", "exit_location LIKE ?")
		args = append(args, code, code+" %")
	}

	query := `DELETE FROM proxies WHERE source = 'free' AND exit_location != '' AND NOT (` + strings.Join(conditions, " OR ") + `)`
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteWithoutExitInfo 删除没有出口信息的代理（仅免费代理）
func (s *Storage) DeleteWithoutExitInfo() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE source = 'free' AND (exit_ip = '' OR exit_location = '')`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DisableBlockedCountries 禁用订阅代理中属于被屏蔽国家的（不删除）
func (s *Storage) DisableBlockedCountries(countryCodes []string) (int64, error) {
	if len(countryCodes) == 0 {
		return 0, nil
	}
	var total int64
	for _, code := range countryCodes {
		res, err := s.db.Exec(
			`UPDATE proxies SET status = 'disabled' WHERE source = 'custom' AND status = 'active' AND (exit_location = ? OR exit_location LIKE ?)`,
			code, code+" %",
		)
		if err != nil {
			return total, err
		}
		affected, _ := res.RowsAffected()
		total += affected
	}
	return total, nil
}

// DisableNotAllowedCountries 禁用订阅代理中不在白名单的（不删除）
func (s *Storage) DisableNotAllowedCountries(allowedCodes []string) (int64, error) {
	if len(allowedCodes) == 0 {
		return 0, nil
	}
	conditions := make([]string, 0, len(allowedCodes)*2)
	args := make([]interface{}, 0, len(allowedCodes)*2)
	for _, code := range allowedCodes {
		conditions = append(conditions, "exit_location = ?", "exit_location LIKE ?")
		args = append(args, code, code+" %")
	}
	query := `UPDATE proxies SET status = 'disabled' WHERE source = 'custom' AND status = 'active' AND exit_location != '' AND NOT (` + strings.Join(conditions, " OR ") + `)`
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Count 返回可用代理数量（仅免费代理，用于 slot 计算）
func (s *Storage) Count() (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM proxies WHERE status IN ('active', 'degraded') AND fail_count < 3 AND source = 'free'`,
	).Scan(&count)
	return count, err
}

// CountAll 返回所有可用代理数量（免费+订阅）
func (s *Storage) CountAll() (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM proxies WHERE status IN ('active', 'degraded') AND fail_count < 3`,
	).Scan(&count)
	return count, err
}

// CountByProtocol 按协议统计数量（仅免费代理，用于 slot 计算）
func (s *Storage) CountByProtocol(protocol string) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM proxies WHERE status IN ('active', 'degraded') AND fail_count < 3 AND source = 'free' AND protocol = ?`,
		protocol,
	).Scan(&count)
	return count, err
}

// IncrementFailCount 增加失败次数
func (s *Storage) IncrementFailCount(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET fail_count = fail_count + 1 WHERE address = ?`,
		address,
	)
	return err
}

// GetByProtocol 按协议获取代理列表
func (s *Storage) GetByProtocol(protocol string) ([]Proxy, error) {
	rows, err := s.db.Query(
		`SELECT `+proxyColumns+`
		 FROM proxies
		 WHERE status IN ('active', 'degraded') AND fail_count < 3 AND protocol = ?
		 ORDER BY latency ASC`, protocol,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, nil
}

// ========== 订阅代理相关方法 ==========

// AddProxyWithSource 新增代理并指定来源和订阅ID
func (s *Storage) AddProxyWithSource(address, protocol, source string, subscriptionID ...int64) error {
	subID := int64(0)
	if len(subscriptionID) > 0 {
		subID = subscriptionID[0]
	}
	result, err := s.db.Exec(
		`INSERT OR IGNORE INTO proxies (address, protocol, source, subscription_id) VALUES (?, ?, ?, ?)`,
		address, protocol, source, subID,
	)
	if err != nil {
		log.Printf("[storage] AddProxyWithSource %s error: %v", address, err)
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		// 已存在，更新 source 和 subscription_id
		_, err = s.db.Exec(`UPDATE proxies SET source = ?, subscription_id = ? WHERE address = ?`, source, subID, address)
	}
	return err
}

// DeleteBySubscriptionID 删除指定订阅的所有代理
func (s *Storage) DeleteBySubscriptionID(subscriptionID int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE subscription_id = ?`, subscriptionID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DisableProxy 禁用代理（软删除，用于订阅代理）
func (s *Storage) DisableProxy(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET status = 'disabled' WHERE address = ?`,
		address,
	)
	return err
}

// EnableProxy 启用代理（从禁用状态恢复，同时清除冷却）
func (s *Storage) EnableProxy(address string) error {
	_, err := s.db.Exec(
		`UPDATE proxies SET status = 'active', fail_count = 0, cooldown_until = NULL WHERE address = ?`,
		address,
	)
	return err
}

// GetDisabledCustomProxies 获取所有被禁用的订阅代理（排除仍在冷却中的，冷却中的不唤醒）
func (s *Storage) GetDisabledCustomProxies() ([]Proxy, error) {
	rows, err := s.db.Query(
		`SELECT `+proxyColumns+`
		 FROM proxies
		 WHERE source = 'custom' AND status = 'disabled'
		   AND (cooldown_until IS NULL OR cooldown_until <= CURRENT_TIMESTAMP)`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, nil
}

// CountBySource 按来源统计可用代理数量
func (s *Storage) CountBySource(source string) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM proxies WHERE source = ? AND status IN ('active', 'degraded') AND fail_count < 3`,
		source,
	).Scan(&count)
	return count, err
}

// DeleteBySource 删除指定来源的所有代理
func (s *Storage) DeleteBySource(source string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM proxies WHERE source = ?`, source)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteCustomProxiesNotIn 删除不在给定地址列表中的订阅代理
func (s *Storage) DeleteCustomProxiesNotIn(addresses []string) (int64, error) {
	if len(addresses) == 0 {
		return s.DeleteBySource("custom")
	}
	placeholders := make([]string, len(addresses))
	args := make([]interface{}, len(addresses))
	for i, addr := range addresses {
		placeholders[i] = "?"
		args[i] = addr
	}
	query := `DELETE FROM proxies WHERE source = 'custom' AND address NOT IN (` + strings.Join(placeholders, ",") + `)`
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ========== 订阅 CRUD ==========

// AddSubscription 添加订阅（自动去重：相同 URL 或 file_path 不重复添加）
func (s *Storage) AddSubscription(name, url, filePath, format string, refreshMin int) (int64, error) {
	// 去重检查
	if url != "" {
		var existID int64
		err := s.db.QueryRow(`SELECT id FROM subscriptions WHERE url = ? AND url != ''`, url).Scan(&existID)
		if err == nil {
			return 0, fmt.Errorf("该订阅 URL 已存在")
		}
	}
	if filePath != "" {
		var existID int64
		err := s.db.QueryRow(`SELECT id FROM subscriptions WHERE file_path = ? AND file_path != ''`, filePath).Scan(&existID)
		if err == nil {
			return 0, fmt.Errorf("该订阅文件已存在")
		}
	}

	res, err := s.db.Exec(
		`INSERT INTO subscriptions (name, url, file_path, format, refresh_min) VALUES (?, ?, ?, ?, ?)`,
		name, url, filePath, format, refreshMin,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CountBySubscriptionID 统计指定订阅的可用/禁用代理数
func (s *Storage) CountBySubscriptionID(subID int64) (active int, disabled int) {
	s.db.QueryRow(
		`SELECT COUNT(*) FROM proxies WHERE subscription_id = ? AND status IN ('active', 'degraded') AND fail_count < 3`,
		subID,
	).Scan(&active)
	s.db.QueryRow(
		`SELECT COUNT(*) FROM proxies WHERE subscription_id = ? AND status = 'disabled'`,
		subID,
	).Scan(&disabled)
	return
}

// AddContributedSubscription 添加访客贡献的订阅
func (s *Storage) AddContributedSubscription(name, url string, refreshMin int) (int64, error) {
	if url == "" {
		return 0, fmt.Errorf("URL 不能为空")
	}
	// 去重
	var existID int64
	err := s.db.QueryRow(`SELECT id FROM subscriptions WHERE url = ? AND url != ''`, url).Scan(&existID)
	if err == nil {
		return 0, fmt.Errorf("该订阅 URL 已存在")
	}

	res, err := s.db.Exec(
		`INSERT INTO subscriptions (name, url, format, refresh_min, contributed) VALUES (?, ?, 'auto', ?, 1)`,
		name, url, refreshMin,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateSubscription 更新订阅
func (s *Storage) UpdateSubscription(id int64, name, url, filePath, format string, refreshMin int) error {
	_, err := s.db.Exec(
		`UPDATE subscriptions SET name = ?, url = ?, file_path = ?, format = ?, refresh_min = ? WHERE id = ?`,
		name, url, filePath, format, refreshMin, id,
	)
	return err
}

// DeleteSubscription 删除订阅
func (s *Storage) DeleteSubscription(id int64) error {
	_, err := s.db.Exec(`DELETE FROM subscriptions WHERE id = ?`, id)
	return err
}

// GetSubscriptions 获取所有订阅
func (s *Storage) GetSubscriptions() ([]Subscription, error) {
	rows, err := s.db.Query(
		`SELECT ` + subColumns + `
		 FROM subscriptions ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		subs = append(subs, *sub)
	}
	return subs, nil
}

// GetSubscription 获取单个订阅
func (s *Storage) GetSubscription(id int64) (*Subscription, error) {
	rows, err := s.db.Query(
		`SELECT ` + subColumns + `
		 FROM subscriptions WHERE id = ?`, id,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		return scanSubscription(rows)
	}
	return nil, fmt.Errorf("subscription %d not found", id)
}

// UpdateSubscriptionFetch 更新订阅的最后拉取时间和代理数
func (s *Storage) UpdateSubscriptionFetch(id int64, proxyCount int) error {
	_, err := s.db.Exec(
		`UPDATE subscriptions SET last_fetch = CURRENT_TIMESTAMP, proxy_count = ? WHERE id = ?`,
		proxyCount, id,
	)
	return err
}

// UpdateSubscriptionSuccess 记录订阅最后一次有可用节点的时间
func (s *Storage) UpdateSubscriptionSuccess(id int64) error {
	_, err := s.db.Exec(
		`UPDATE subscriptions SET last_success = CURRENT_TIMESTAMP WHERE id = ?`, id,
	)
	return err
}

// GetStaleSubscriptions 获取连续 N 天无可用节点的订阅
func (s *Storage) GetStaleSubscriptions(staleDays int) ([]Subscription, error) {
	rows, err := s.db.Query(
		`SELECT `+subColumns+`
		 FROM subscriptions
		 WHERE status = 'active'
		   AND (last_success IS NULL OR JULIANDAY('now') - JULIANDAY(last_success) > ?)
		   AND JULIANDAY('now') - JULIANDAY(created_at) > ?`,
		staleDays, staleDays,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		subs = append(subs, *sub)
	}
	return subs, nil
}

// ToggleSubscription 切换订阅状态
func (s *Storage) ToggleSubscription(id int64) error {
	_, err := s.db.Exec(
		`UPDATE subscriptions SET status = CASE WHEN status = 'active' THEN 'paused' ELSE 'active' END WHERE id = ?`,
		id,
	)
	return err
}

// scanSubscription 扫描订阅行数据
// subColumns 订阅表查询列
const subColumns = `id, name, url, file_path, format, refresh_min, last_fetch, last_success, status, proxy_count, created_at, contributed`

func scanSubscription(rows *sql.Rows) (*Subscription, error) {
	sub := &Subscription{}
	var lastFetch, lastSuccess sql.NullTime
	var contributed int
	if err := rows.Scan(&sub.ID, &sub.Name, &sub.URL, &sub.FilePath, &sub.Format,
		&sub.RefreshMin, &lastFetch, &lastSuccess, &sub.Status, &sub.ProxyCount, &sub.CreatedAt, &contributed); err != nil {
		return nil, err
	}
	if lastFetch.Valid {
		sub.LastFetch = lastFetch.Time
	}
	if lastSuccess.Valid {
		sub.LastSuccess = lastSuccess.Time
	}
	sub.Contributed = contributed == 1
	return sub, nil
}

// Close 关闭数据库
func (s *Storage) Close() error {
	return s.db.Close()
}

// GetDB 获取数据库实例（供其他模块使用）
func (s *Storage) GetDB() *sql.DB {
	return s.db
}
