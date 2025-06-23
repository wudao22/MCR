package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	_ "github.com/mattn/go-sqlite3"
)

// RCON包类型常量
const (
	SERVERDATA_AUTH           = 3
	SERVERDATA_AUTH_RESPONSE  = 2
	SERVERDATA_EXECCOMMAND    = 2
	SERVERDATA_RESPONSE_VALUE = 0
)

// RCON数据包结构
type RCONPacket struct {
	Length int32
	ID     int32
	Type   int32
	Body   string
}

// RCON客户端结构
type RCONClient struct {
	conn     net.Conn
	address  string
	password string
	timeout  time.Duration
}

// 创建新的RCON客户端
func NewRCONClient(address, password string) *RCONClient {
	return &RCONClient{
		address:  address,
		password: password,
		timeout:  10 * time.Second,
	}
}

// 连接到RCON服务器
func (r *RCONClient) Connect() error {
	conn, err := net.DialTimeout("tcp", r.address, r.timeout)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	r.conn = conn
	return nil
}

// 关闭连接
func (r *RCONClient) Close() error {
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

// 发送数据包
func (r *RCONClient) sendPacket(packet *RCONPacket) error {
	// 计算包长度 (ID + Type + Body + 两个null字节)
	packet.Length = 4 + 4 + int32(len(packet.Body)) + 2

	buf := new(bytes.Buffer)

	// 写入长度、ID、类型
	binary.Write(buf, binary.LittleEndian, packet.Length)
	binary.Write(buf, binary.LittleEndian, packet.ID)
	binary.Write(buf, binary.LittleEndian, packet.Type)

	// 写入消息体和两个null字节
	buf.WriteString(packet.Body)
	buf.WriteByte(0)
	buf.WriteByte(0)

	// 设置写入超时
	r.conn.SetWriteDeadline(time.Now().Add(r.timeout))
	_, err := r.conn.Write(buf.Bytes())
	return err
}

// 接收数据包
func (r *RCONClient) receivePacket() (*RCONPacket, error) {
	// 设置读取超时
	r.conn.SetReadDeadline(time.Now().Add(r.timeout))

	// 读取包长度
	var length int32
	err := binary.Read(r.conn, binary.LittleEndian, &length)
	if err != nil {
		return nil, err
	}

	// 读取剩余数据
	data := make([]byte, length)
	_, err = io.ReadFull(r.conn, data)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(data)

	var id, pType int32
	binary.Read(buf, binary.LittleEndian, &id)
	binary.Read(buf, binary.LittleEndian, &pType)

	// 读取消息体 (去掉末尾的两个null字节)
	bodyData := make([]byte, length-8-2)
	buf.Read(bodyData)

	return &RCONPacket{
		Length: length,
		ID:     id,
		Type:   pType,
		Body:   string(bodyData),
	}, nil
}

// 身份验证
func (r *RCONClient) Authenticate() error {
	// 发送认证请求
	authPacket := &RCONPacket{
		ID:   1,
		Type: SERVERDATA_AUTH,
		Body: r.password,
	}

	err := r.sendPacket(authPacket)
	if err != nil {
		return fmt.Errorf("发送认证请求失败: %v", err)
	}

	// 接收认证响应
	response, err := r.receivePacket()
	if err != nil {
		return fmt.Errorf("接收认证响应失败: %v", err)
	}

	if response.ID != 1 {
		return fmt.Errorf("认证失败: 密码错误")
	}

	return nil
}

// 执行命令
func (r *RCONClient) ExecuteCommand(command string) (string, error) {
	// 发送命令执行请求
	cmdPacket := &RCONPacket{
		ID:   2,
		Type: SERVERDATA_EXECCOMMAND,
		Body: command,
	}

	err := r.sendPacket(cmdPacket)
	if err != nil {
		return "", fmt.Errorf("发送命令失败: %v", err)
	}

	// 接收命令响应
	response, err := r.receivePacket()
	if err != nil {
		return "", fmt.Errorf("接收命令响应失败: %v", err)
	}

	return response.Body, nil
}

// Minecraft命令列表 (用于自动补全)
var minecraftCommands = []string{
	"advancement", "attribute", "ban", "ban-ip", "banlist", "bossbar",
	"clear", "clone", "data", "datapack", "debug", "defaultgamemode",
	"deop", "difficulty", "effect", "enchant", "execute", "experience",
	"fill", "forceload", "function", "gamemode", "gamerule", "give",
	"help", "kick", "kill", "list", "locate", "locatebiome", "loot",
	"me", "msg", "op", "pardon", "pardon-ip", "particle", "playsound",
	"recipe", "reload", "replaceitem", "save-all", "save-off", "save-on",
	"say", "schedule", "scoreboard", "seed", "setblock", "setidletimeout",
	"setworldspawn", "spawnpoint", "spectate", "spreadplayers", "stop",
	"stopsound", "summon", "tag", "team", "teleport", "tell", "tellraw",
	"time", "title", "tp", "trigger", "weather", "whitelist", "worldborder",
	"xp",
}

// 服务器配置结构
type ServerConfig struct {
	ID       int
	Name     string
	Address  string // 保存用户输入的原始地址（域名/IP）
	Password string
	LastUsed time.Time
}

// 数据库管理器
type ConfigDB struct {
	db  *sql.DB
	key []byte // 用于密码加密的密钥
}

// 创建新的配置数据库管理器
func NewConfigDB() (*ConfigDB, error) {
	// 打开数据库
	db, err := sql.Open("sqlite3", "rcon_config.db")
	if err != nil {
		return nil, fmt.Errorf("无法打开数据库: %v", err)
	}

	// 生成或获取加密密钥
	key := generateOrGetKey()

	configDB := &ConfigDB{
		db:  db,
		key: key,
	}

	// 初始化数据库表
	err = configDB.initTables()
	if err != nil {
		db.Close()
		return nil, err
	}

	return configDB, nil
}

// 生成或获取加密密钥
func generateOrGetKey() []byte {
	keyFile := "rcon.key"

	// 尝试读取现有密钥
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		return data
	}

	// 生成新密钥
	key := make([]byte, 32)
	rand.Read(key)

	// 保存密钥到文件
	os.WriteFile(keyFile, key, 0600)

	return key
}

// 初始化数据库表
func (c *ConfigDB) initTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS server_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		address TEXT NOT NULL,
		password TEXT NOT NULL,
		last_used DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE INDEX IF NOT EXISTS idx_last_used ON server_configs(last_used DESC);
	`

	_, err := c.db.Exec(query)
	return err
}

// 加密密码
func (c *ConfigDB) encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// 解密密码
func (c *ConfigDB) decryptPassword(encryptedPassword string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("密码数据损坏")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// 保存服务器配置
func (c *ConfigDB) SaveConfig(config *ServerConfig) error {
	encryptedPassword, err := c.encryptPassword(config.Password)
	if err != nil {
		return fmt.Errorf("密码加密失败: %v", err)
	}

	query := `
	INSERT OR REPLACE INTO server_configs (name, address, password, last_used)
	VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`

	_, err = c.db.Exec(query, config.Name, config.Address, encryptedPassword)
	if err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	return nil
}

// 获取所有服务器配置
func (c *ConfigDB) GetAllConfigs() ([]ServerConfig, error) {
	query := `
	SELECT id, name, address, password, last_used
	FROM server_configs
	ORDER BY last_used DESC
	`

	rows, err := c.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []ServerConfig
	for rows.Next() {
		var config ServerConfig
		var encryptedPassword string
		var lastUsedStr string

		err := rows.Scan(&config.ID, &config.Name, &config.Address,
			&encryptedPassword, &lastUsedStr)
		if err != nil {
			continue // 跳过损坏的记录
		}

		// 解密密码
		config.Password, err = c.decryptPassword(encryptedPassword)
		if err != nil {
			continue // 跳过无法解密的记录
		}

		// 解析时间
		config.LastUsed, _ = time.Parse("2006-01-02 15:04:05", lastUsedStr)

		configs = append(configs, config)
	}

	return configs, nil
}

// 根据名称获取配置
func (c *ConfigDB) GetConfigByName(name string) (*ServerConfig, error) {
	query := `
	SELECT id, name, address, password, last_used
	FROM server_configs
	WHERE name = ?
	`

	var config ServerConfig
	var encryptedPassword string
	var lastUsedStr string

	err := c.db.QueryRow(query, name).Scan(&config.ID, &config.Name,
		&config.Address, &encryptedPassword, &lastUsedStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("配置 '%s' 不存在", name)
		}
		return nil, err
	}

	// 解密密码
	config.Password, err = c.decryptPassword(encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("密码解密失败: %v", err)
	}

	// 解析时间
	config.LastUsed, _ = time.Parse("2006-01-02 15:04:05", lastUsedStr)

	return &config, nil
}

// 更新最后使用时间
func (c *ConfigDB) UpdateLastUsed(name string) error {
	query := `UPDATE server_configs SET last_used = CURRENT_TIMESTAMP WHERE name = ?`
	_, err := c.db.Exec(query, name)
	return err
}

// 删除配置
func (c *ConfigDB) DeleteConfig(name string) error {
	query := `DELETE FROM server_configs WHERE name = ?`
	result, err := c.db.Exec(query, name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("配置 '%s' 不存在", name)
	}

	return nil
}

// 关闭数据库连接
func (c *ConfigDB) Close() error {
	return c.db.Close()
}

// 显示保存的配置列表
func showSavedConfigs(configDB *ConfigDB) {
	configs, err := configDB.GetAllConfigs()
	if err != nil {
		fmt.Printf("获取配置列表失败: %v\n", err)
		return
	}

	if len(configs) == 0 {
		fmt.Println("没有保存的服务器配置")
		return
	}

	fmt.Println("\n已保存的服务器配置:")
	fmt.Println("序号 | 名称 | 地址 | 最后使用时间")
	fmt.Println("-----|------|------|-------------")

	for i, config := range configs {
		lastUsed := config.LastUsed.Format("2006-01-02 15:04")
		fmt.Printf("%2d   | %-10s | %-20s | %s\n",
			i+1, config.Name, config.Address, lastUsed)
	}
	fmt.Println()
}

// 选择服务器配置
func selectServerConfig(configDB *ConfigDB) (*ServerConfig, error) {
	configs, err := configDB.GetAllConfigs()
	if err != nil {
		return nil, fmt.Errorf("获取配置列表失败: %v", err)
	}

	if len(configs) == 0 {
		return nil, nil // 没有保存的配置
	}

	fmt.Println("选择连接方式:")
	fmt.Println("1. 使用保存的服务器配置")
	fmt.Println("2. 输入新的服务器地址")
	fmt.Print("请选择 (1/2): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice != "1" {
		return nil, nil // 选择输入新地址
	}

	// 显示配置列表
	showSavedConfigs(configDB)

	fmt.Print("请输入配置序号或名称: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	// 尝试解析为数字
	if num, err := strconv.Atoi(input); err == nil {
		if num >= 1 && num <= len(configs) {
			selected := configs[num-1]
			return &selected, nil
		} else {
			return nil, fmt.Errorf("序号 %d 超出范围", num)
		}
	}

	// 按名称查找
	config, err := configDB.GetConfigByName(input)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// 询问是否保存配置
func askToSaveConfig(configDB *ConfigDB, address, password string) {
	fmt.Print("\n是否保存此服务器配置? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "y" && response != "yes" {
		return
	}

	fmt.Print("请输入配置名称: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	if name == "" {
		fmt.Println("配置名称不能为空，取消保存")
		return
	}

	config := &ServerConfig{
		Name:     name,
		Address:  address,
		Password: password,
	}

	err := configDB.SaveConfig(config)
	if err != nil {
		fmt.Printf("保存配置失败: %v\n", err)
	} else {
		fmt.Printf("配置 '%s' 保存成功!\n", name)
	}
}

// 解析地址，支持主机名解析，如果没有端口则使用默认端口25575
func parseAddress(input string) (string, error) {
	var host, port string

	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) != 2 {
			return "", fmt.Errorf("地址格式错误，应为 host:port")
		}
		host = parts[0]
		port = parts[1]
	} else {
		host = input
		port = "25575" // 默认端口
	}

	// 尝试解析主机名
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("无法解析主机名 '%s': %v", host, err)
	}

	// 优先使用IPv4地址
	var resolvedIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			resolvedIP = ip.String()
			break
		}
	}

	// 如果没有IPv4地址，使用第一个IPv6地址
	if resolvedIP == "" && len(ips) > 0 {
		resolvedIP = ips[0].String()
	}

	if resolvedIP == "" {
		return "", fmt.Errorf("无法为主机名 '%s' 找到有效的IP地址", host)
	}

	return net.JoinHostPort(resolvedIP, port), nil
}

func main() {
	fmt.Println("=== Minecraft RCON 客户端 ===")
	fmt.Println("高性能 Go 实现，支持命令自动补全、主机名解析和配置保存")
	fmt.Println()

	// 初始化配置数据库
	configDB, err := NewConfigDB()
	if err != nil {
		fmt.Printf("初始化配置数据库失败: %v\n", err)
		return
	}
	defer configDB.Close()

	var addressInput, password string
	var selectedConfig *ServerConfig

	// 尝试选择已保存的配置
	selectedConfig, err = selectServerConfig(configDB)
	if err != nil {
		fmt.Printf("选择配置失败: %v\n", err)
		return
	}

	if selectedConfig != nil {
		// 使用保存的配置
		addressInput = selectedConfig.Address
		password = selectedConfig.Password
		fmt.Printf("使用保存的配置: %s (%s)\n", selectedConfig.Name, selectedConfig.Address)

		// 更新最后使用时间
		configDB.UpdateLastUsed(selectedConfig.Name)
	} else {
		// 手动输入新配置
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("请输入服务器地址 (支持IP/主机名，默认端口25575): ")
		addressInput, _ = reader.ReadString('\n')
		addressInput = strings.TrimSpace(addressInput)

		if addressInput == "" {
			fmt.Println("错误: 请输入有效的服务器地址")
			return
		}

		fmt.Print("请输入RCON密码: ")
		password, _ = reader.ReadString('\n')
		password = strings.TrimSpace(password)

		if password == "" {
			fmt.Println("错误: 请输入RCON密码")
			return
		}
	}

	// 解析地址，支持主机名解析
	address, err := parseAddress(addressInput)
	if err != nil {
		fmt.Printf("地址解析错误: %v\n", err)
		return
	}
	fmt.Printf("连接地址: %s\n", address)

	// 创建RCON客户端
	client := NewRCONClient(address, password)

	// 连接到服务器
	fmt.Print("正在连接服务器...")
	err = client.Connect()
	if err != nil {
		fmt.Printf("连接失败: %v\n", err)
		return
	}
	defer client.Close()
	fmt.Println(" 连接成功!")

	// 进行身份验证
	fmt.Print("正在进行身份验证...")
	err = client.Authenticate()
	if err != nil {
		fmt.Printf("验证失败: %v\n", err)
		return
	}
	fmt.Println(" 验证成功!")

	// 如果是新配置，询问是否保存
	if selectedConfig == nil {
		askToSaveConfig(configDB, addressInput, password)
	}

	// 配置readline用于命令补全和输入
	config := &readline.Config{
		Prompt:            "RCON> ",
		HistoryFile:       ".rcon_history",
		AutoComplete:      readline.NewPrefixCompleter(createCompleterItems()...),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	}

	rl, err := readline.NewEx(config)
	if err != nil {
		fmt.Printf("初始化命令行失败: %v\n", err)
		return
	}
	defer rl.Close()

	fmt.Println("\n已连接到Minecraft服务器!")
	fmt.Println("输入 'quit' 或 'exit' 退出程序，Ctrl+C 中断")
	fmt.Println("使用 Tab 键进行命令自动补全，上下箭头浏览历史命令")
	fmt.Println("输入 'config' 查看配置管理命令")
	fmt.Println("----------------------------------------")

	// 命令循环
	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					fmt.Println("\n使用 'quit' 或 'exit' 退出程序")
					continue
				} else {
					fmt.Println("\n命令被中断")
					continue
				}
			} else if err == io.EOF {
				fmt.Println("\n正在退出...")
				break
			}
			fmt.Printf("读取输入错误: %v\n", err)
			continue
		}

		command := strings.TrimSpace(line)
		if command == "" {
			continue
		}

		// 检查特殊命令
		switch command {
		case "quit", "exit":
			fmt.Println("正在断开连接...")
			goto exit

		case "config":
			fmt.Println("\n配置管理命令:")
			fmt.Println("config list    - 显示所有保存的配置")
			fmt.Println("config delete <名称> - 删除指定配置")
			continue

		case "config list":
			showSavedConfigs(configDB)
			continue
		}

		// 处理config delete命令
		if strings.HasPrefix(command, "config delete ") {
			configName := strings.TrimSpace(strings.TrimPrefix(command, "config delete "))
			if configName == "" {
				fmt.Println("请指定要删除的配置名称")
				continue
			}

			err := configDB.DeleteConfig(configName)
			if err != nil {
				fmt.Printf("删除配置失败: %v\n", err)
			} else {
				fmt.Printf("配置 '%s' 已删除\n", configName)
			}
			continue
		}

		// 执行Minecraft命令
		response, err := client.ExecuteCommand(command)
		if err != nil {
			fmt.Printf("命令执行失败: %v\n", err)
			continue
		}

		// 显示响应
		if response != "" {
			fmt.Printf("服务器响应: %s\n", response)
		} else {
			fmt.Println("命令执行成功 (无响应)")
		}
	}

exit:
	fmt.Println("再见!")
}

// 创建自动补全项目
func createCompleterItems() []readline.PrefixCompleterInterface {
	var items []readline.PrefixCompleterInterface
	for _, cmd := range minecraftCommands {
		items = append(items, readline.PcItem(cmd))
	}
	return items
}
