package capture

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/whynot00/tg-ip-sniffer/internal/filters"
	"github.com/whynot00/tg-ip-sniffer/internal/models"
	"github.com/whynot00/tg-ip-sniffer/internal/ports"
)

type bpfHandle interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	SetBPFFilter(string) error
	LinkType() layers.LinkType
	Close()
}
type dumpWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
}

func newReaderForTest(tr *ports.Tracker, h bpfHandle, w dumpWriter) *NetworkReader {
	return &NetworkReader{
		tracker:    tr,
		handle:     h,
		outCh:      make(chan *models.IPRaw, 16),
		dumpWriter: w,
	}
}

// NetworkReader отвечает за захват пакетов с интерфейса и
// выдачу их в канал, а также за установку/обновление BPF-фильтра.
type NetworkReader struct {
	tracker *ports.Tracker
	handle  bpfHandle
	outCh   chan *models.IPRaw

	customBPF string // фильтр, заданный пользователем через --bpf

	// настройки и состояния дампа в файл
	dumpEnabled bool
	dumpPath    string
	dumpWriter  dumpWriter
	dumpFile    *os.File
}

// NewReader создаёт и инициализирует захватчик пакетов.
func NewReader(ctx context.Context, ifaceName, appName string) *NetworkReader {
	r := &NetworkReader{
		tracker: ports.NewTracker(appName),
		outCh:   make(chan *models.IPRaw, 1024),
	}

	// запуск трекера портов Telegram
	go r.tracker.StartPolling(ctx)

	// ждём появления первых портов
	for {
		if len(r.tracker.Snapshot()) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond) // даём CPU отдохнуть
	}

	// открываем интерфейс в режиме захвата
	h, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	r.handle = h

	return r
}

// Events возвращает канал с "сырыми" IP-событиями.
func (r *NetworkReader) Events() <-chan *models.IPRaw { return r.outCh }

// Start запускает цикл чтения пакетов и обновления фильтра.
func (r *NetworkReader) Start(ctx context.Context) {
	// готовим pcap-дамп при необходимости
	if err := r.initDumpWriter(); err != nil {
		log.Printf("pcap dump init error: %v", err)
	} else if r.dumpEnabled && r.dumpPath != "" {
		log.Printf("pcap dump to: %s", r.dumpPath)
	}
	defer r.closeDump()
	defer func() {
		if r.handle != nil {
			r.handle.Close()
		}
	}()

	updateCh := r.tracker.Updates()
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	packets := packetSource.Packets()

	// основной цикл вынесен в runLoop
	r.runLoop(ctx, packets, updateCh)
}

// SetCustomBPF задаёт пользовательский BPF-фильтр.
func (r *NetworkReader) SetCustomBPF(filter string) {
	r.customBPF = filter
}

// setBPF строит фильтр по текущим портам Telegram и применяет его.
func (r *NetworkReader) setBPF() error {
	filter := filters.BuildPorts(r.tracker.Snapshot())
	if filter == "" {
		// пустой фильтр — валидно, снимаем ограничения
		return r.handle.SetBPFFilter("")
	}
	return r.handle.SetBPFFilter(filter)
}

// newStoppedTimer возвращает таймер, уже переведённый в стоп.
func newStoppedTimer() *time.Timer {
	t := time.NewTimer(time.Hour)
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	return t
}

// drainTimer сбрасывает значение из канала таймера, если оно там есть.
func drainTimer(t *time.Timer) {
	select {
	case <-t.C:
	default:
	}
}

// runLoop — основной цикл чтения пакетов, обновления фильтра и записи дампа.
func (r *NetworkReader) runLoop(
	ctx context.Context,
	packets <-chan gopacket.Packet,
	updateCh <-chan struct{},
) {
	debounce := newStoppedTimer()
	dirty := true // флаг "фильтр требует обновления"

	apply := func() {
		if !dirty {
			return
		}
		if r.customBPF != "" {
			// приоритет у пользовательского фильтра
			if err := r.handle.SetBPFFilter(r.customBPF); err != nil {
				log.Printf("SetBPFFilter error: %v", err)
			} else {
				log.Printf("custom BPF applied: %s", r.customBPF)
			}
		} else {
			// стандартная логика по портам Telegram
			if err := r.setBPF(); err != nil {
				log.Printf("setBPF error: %v", err)
			}
		}
		dirty = false
	}

	for {
		select {
		case <-updateCh:
			// пришло обновление портов — перезапустим дебаунс
			dirty = true
			if !debounce.Stop() {
				drainTimer(debounce)
			}
			debounce.Reset(500 * time.Millisecond)

		case <-debounce.C:
			// сработал дебаунс — применяем фильтр
			apply()

		case packet := <-packets:
			if packet == nil {
				close(r.outCh)
				return
			}

			// запись пакета в дамп, если включено
			if r.dumpWriter != nil {
				ci := packet.Metadata().CaptureInfo
				if err := r.dumpWriter.WritePacket(ci, packet.Data()); err != nil {
					log.Printf("pcap dump write error: %v", err)
				}
			}

			// извлечение IP-данных и отправка в канал
			if ipInfo := extractIPInfo(packet); ipInfo != nil {
				r.outCh <- ipInfo
			}

			// на старте фильтр применяем сразу после первого пакета
			apply()

		case <-ctx.Done():
			close(r.outCh)
			return
		}
	}
}
