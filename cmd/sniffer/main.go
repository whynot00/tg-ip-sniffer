package main

import (
	"context"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whynot00/tg-ip-sniffer/internal/capture"
	"github.com/whynot00/tg-ip-sniffer/internal/netutil"
	"github.com/whynot00/tg-ip-sniffer/internal/telegram"
	"github.com/whynot00/tg-ip-sniffer/internal/ui/tui"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// Поведение прежнее: по умолчанию en0 и Telegram.
	iface := getenv("SNIFFER_IFACE", "en0")
	appName := getenv("SNIFFER_APP", "Telegram")

	ctx := context.Background()

	reader := capture.NewReader(ctx, iface, appName)
	go reader.Start(ctx)

	localIP, _ := netutil.GetLocalIP(iface)

	m := tui.NewModel(
		reader.Events(),
		localIP,
		telegram.LoadIP(),
	)

	m.RefreshTables()

	// UI
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Println("run error:", err)
	}

	// Даем UI успеть завершить вывод (косметика; логика не меняется)
	time.Sleep(50 * time.Millisecond)
}
