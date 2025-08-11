package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/whynot00/tg-ip-sniffer/internal/capture"
	"github.com/whynot00/tg-ip-sniffer/internal/netutil"
	"github.com/whynot00/tg-ip-sniffer/internal/platform"
	"github.com/whynot00/tg-ip-sniffer/internal/telegram"
	"github.com/whynot00/tg-ip-sniffer/internal/ui/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// Флаги CLI
	ifaceFlag := flag.String("iface", "", "сетевой интерфейс для захвата")
	bpfFlag := flag.String("bpf", "", "BPF‑фильтр (игнорирует автофильтр Telegram)")
	otherMaxAgeFlag := flag.Int("other-max-age", 90, "максимальный возраст активности (сек) для отображения «Иных IP»")
	minPacketsFlag := flag.Int("min-packets", 0, "минимальное число пакетов для отображения IP")
	noDump := flag.Bool("no-dump", false, "не сохранять трафик в pcap‑файл")
	flag.Parse()

	// Проверка Npcap (Windows). На других ОС вернёт nil.
	if err := platform.CheckNpcap(); err != nil {
		log.Println("Npcap не установлен или работает некорректно:", err)
		os.Exit(1)
	}

	appName := platform.TelegramProcessName()
	// Ждём Telegram только если фильтр не задан вручную.
	if *bpfFlag == "" {
		if ok := platform.WaitForProcess(appName, 60*time.Second); !ok {
			log.Println("Telegram не запущен. Завершаем.")
			os.Exit(1)
		}
	}

	iface := *ifaceFlag
	if iface == "" {
		iface = platform.DefaultInterface()
	}
	if iface == "" {
		log.Println("Не удалось определить сетевой интерфейс. Укажите его через флаг --iface.")
		os.Exit(1)
	}

	// Контекст жизни приложения: отменяется после выхода из UI.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := capture.NewReader(ctx, iface, appName)
	if !*noDump {
		reader.EnableDump("") // пустой путь → captures/tg-YYYYMMDD-HHMMSS.pcap
	}
	if *bpfFlag != "" {
		reader.SetCustomBPF(*bpfFlag)
	}
	go reader.Start(ctx)

	localIP, err := netutil.GetLocalIP(iface)
	if err != nil {
		// Не критично: просто покажем пустое значение в заголовке UI.
		log.Println("Не удалось получить локальный IP для интерфейса", iface, ":", err)
	}

	m := tui.NewModel(
		reader.Events(),
		localIP,
		telegram.LoadIP(),
	)
	m.OtherMaxAge = time.Duration(*otherMaxAgeFlag) * time.Second
	m.MinPackets = *minPacketsFlag
	m.RefreshTables()

	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		log.Println("Ошибка UI:", err)
		os.Exit(1)
	}

	// По выходу из UI отменяем контекст — фоновые горутины завершатся.
	cancel()
}
