package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/whynot00/tg-ip-sniffer/internal/capture"
	"github.com/whynot00/tg-ip-sniffer/internal/netutil"
	"github.com/whynot00/tg-ip-sniffer/internal/platform"
	"github.com/whynot00/tg-ip-sniffer/internal/telegram"
	"github.com/whynot00/tg-ip-sniffer/internal/ui/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// новые флаги
	ifaceFlag := flag.String("iface", "", "сетевой интерфейс для захвата")
	bpfFlag := flag.String("bpf", "", "BPF-фильтр (игнорирует автофильтр Telegram)")
	otherMaxAgeFlag := flag.Int("other-max-age", 90, "максимальный возраст активности (сек) для отображения 'Иных IP'")
	minPacketsFlag := flag.Int("min-packets", 0, "минимальное число пакетов для отображения IP")

	noDump := flag.Bool("no-dump", false, "не сохранять трафик в pcap-файл")
	flag.Parse()

	if err := platform.CheckNpcap(); err != nil {
		fmt.Println("Npcap не установлен или работает некорректно.")
		return
	}

	appName := platform.TelegramProcessName()
	if *bpfFlag == "" { // ждем Telegram только если фильтр не задан вручную
		if ok := platform.WaitForProcess(appName, 60*time.Second); !ok {
			fmt.Println("Telegram не запущен. Завершаем.")
			return
		}
	}

	iface := *ifaceFlag
	if iface == "" {
		iface = platform.DefaultInterface()
	}
	if iface == "" {
		fmt.Println("Не удалось определить интерфейс.")
		return
	}

	ctx := context.Background()

	reader := capture.NewReader(ctx, iface, appName)
	if !*noDump {
		reader.EnableDump("")
	}
	if *bpfFlag != "" {
		reader.SetCustomBPF(*bpfFlag) // надо добавить метод в Reader
	}

	go reader.Start(ctx)

	localIP, _ := netutil.GetLocalIP(iface)

	m := tui.NewModel(
		reader.Events(),
		localIP,
		telegram.LoadIP(),
	)
	m.OtherMaxAge = time.Duration(*otherMaxAgeFlag) * time.Second
	m.MinPackets = *minPacketsFlag

	m.RefreshTables()

	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Println("run error:", err)
	}
	time.Sleep(50 * time.Millisecond)
}
