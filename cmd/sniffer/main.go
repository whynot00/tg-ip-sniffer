package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/whynot00/tg-ip-sniffer/internal/capture"
	"github.com/whynot00/tg-ip-sniffer/internal/netutil"
	"github.com/whynot00/tg-ip-sniffer/internal/platform"
	"github.com/whynot00/tg-ip-sniffer/internal/telegram"
	"github.com/whynot00/tg-ip-sniffer/internal/ui/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	noDump := flag.Bool("no-dump", false, "не сохранять трафик в pcap-файл")
	flag.Parse()

	if err := platform.CheckNpcap(); err != nil {
		fmt.Println("Похоже, на этой машине нет Npcap или он работает некорректно.")
		fmt.Println("Скачайте и установите Npcap (галочка \"WinPcap API-compatible mode\") по ссылке:")
		fmt.Println("https://nmap.org/npcap/")
		fmt.Println()
		fmt.Println("После установки перезапустите эту программу от имени администратора.")
		fmt.Scanf("")
		return
	}

	appName := platform.TelegramProcessName()
	if ok := platform.WaitForProcess(appName, 60*time.Second); !ok {
		fmt.Println("Telegram не запущен. Захват не стартовал. Запусти Telegram и перезапусти программу.")
		return
	}

	iface := platform.DefaultInterface()
	if iface == "" {
		fmt.Println("Не удалось определить сетевой интерфейс. Укажи его вручную флагом или в коде.")
		return
	}

	ctx := context.Background()

	reader := capture.NewReader(ctx, iface, appName)
	if !*noDump {
		reader.EnableDump("") // пустая строка → путь по умолчанию
	}

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

	// time.Sleep(time.Hour)
}
