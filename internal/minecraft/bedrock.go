package minecraft

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Protocol constants
const (
	RaknetMagic        = "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
	UnconnectedPing    = 0x01
	UnconnectedPong    = 0x1c
	MaxPacketSize      = 1492
	DefaultBedrockPort = 19132
)

// ServerInfo represents Bedrock server information
type ServerInfo struct {
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Edition     string    `json:"edition"`
	MOTD        string    `json:"motd"`
	Protocol    int       `json:"protocol"`
	Version     string    `json:"version"`
	Players     Players   `json:"players"`
	GameMode    string    `json:"gamemode"`
	Timestamp   time.Time `json:"timestamp"`
	Latency    int64     `json:"latency_ms"`
	Plugins    []string  `json:"plugins,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Players struct {
	Online int `json:"online"`
	Max    int `json:"max"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	CVE         string   `json:"cve,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
}

// BedrockScanner handles Minecraft Bedrock server scanning
type BedrockScanner struct {
	timeout     time.Duration
	rateLimiter *RateLimiter
}

func NewBedrockScanner(timeout time.Duration) *BedrockScanner {
	return &BedrockScanner{
		timeout:     timeout,
		rateLimiter: NewRateLimiter(2, time.Second), // 2 queries per second max
	}
}

// ScanServer performs a comprehensive scan of a Bedrock server
func (bs *BedrockScanner) ScanServer(ctx context.Context, address string, port int) (*ServerInfo, error) {
	if err := bs.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	info := &ServerInfo{
		Address:   address,
		Port:     port,
		Timestamp: time.Now(),
	}

	// Create UDP connection
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", address, port), bs.timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	// Send unconnected ping
	start := time.Now()
	if err := bs.sendPing(conn); err != nil {
		return nil, fmt.Errorf("ping failed: %v", err)
	}

	// Receive pong
	response, err := bs.receivePong(conn)
	if err != nil {
		return nil, fmt.Errorf("pong failed: %v", err)
	}

	info.Latency = time.Since(start).Milliseconds()

	// Parse server data
	if err := bs.parseServerData(response, info); err != nil {
		return nil, fmt.Errorf("parse failed: %v", err)
	}

	// Check for known vulnerabilities
	info.Vulnerabilities = bs.checkVulnerabilities(info.Version)

	return info, nil
}

func (bs *BedrockScanner) sendPing(conn net.Conn) error {
	pingTime := time.Now().Unix()
	
	buf := new(bytes.Buffer)
	buf.WriteByte(UnconnectedPing)
	binary.Write(buf, binary.BigEndian, pingTime)
	buf.WriteString(RaknetMagic)
	
	_, err := conn.Write(buf.Bytes())
	return err
}

func (bs *BedrockScanner) receivePong(conn net.Conn) ([]byte, error) {
	response := make([]byte, MaxPacketSize)
	conn.SetReadDeadline(time.Now().Add(bs.timeout))
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	
	if response[0] != UnconnectedPong {
		return nil, fmt.Errorf("invalid response type: %d", response[0])
	}
	
	return response[1:n], nil
}

func (bs *BedrockScanner) parseServerData(data []byte, info *ServerInfo) error {
	// Skip ping time and magic
	data = data[8+16:]
	
	// Server data is in this format:
	// EDITION;MOTD;Protocol;Version;Players;MaxPlayers;ServerID;SubMOTD;Gamemode;.....
	parts := bytes.Split(data, []byte(";"))
	if len(parts) < 9 {
		return fmt.Errorf("invalid server data format")
	}

	info.Edition = string(parts[0])
	info.MOTD = string(parts[1])
	fmt.Sscanf(string(parts[2]), "%d", &info.Protocol)
	info.Version = string(parts[3])
	fmt.Sscanf(string(parts[4]), "%d", &info.Players.Online)
	fmt.Sscanf(string(parts[5]), "%d", &info.Players.Max)
	info.GameMode = string(parts[8])

	// Parse plugins if available (usually in MOTD or SubMOTD)
	info.Plugins = bs.extractPlugins(string(parts[1]) + string(parts[7]))

	return nil
}

func (bs *BedrockScanner) extractPlugins(data string) []string {
	// This is a basic implementation - in reality, you'd want a more sophisticated
	// plugin detection system based on known signatures and patterns
	var plugins []string
	// Example plugin detection (customize based on known patterns)
	knownPlugins := []string{"EssentialsX", "WorldEdit", "CoreProtect"}
	
	for _, plugin := range knownPlugins {
		if bytes.Contains([]byte(data), []byte(plugin)) {
			plugins = append(plugins, plugin)
		}
	}
	
	return plugins
}

func (bs *BedrockScanner) checkVulnerabilities(version string) []Vulnerability {
	// This would be connected to a CVE database in production
	// For now, returning a sample vulnerability for demonstration
	var vulns []Vulnerability
	
	// Example vulnerability check
	if version < "1.16" {
		vulns = append(vulns, Vulnerability{
			ID:          "COMP-MC-001",
			CVE:         "CVE-2020-XXXX",
			Severity:    "HIGH",
			Description: "Remote code execution vulnerability in Bedrock server versions below 1.16",
			References:  []string{"https://example.com/cve-2020-xxxx"},
		})
	}
	
	return vulns
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens chan struct{}
	tick   *time.Ticker
}

func NewRateLimiter(rate int, per time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens: make(chan struct{}, rate),
		tick:   time.NewTicker(per / time.Duration(rate)),
	}

	// Fill token bucket
	for i := 0; i < rate; i++ {
		rl.tokens <- struct{}{}
	}

	go func() {
		for range rl.tick.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()

	return rl
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
