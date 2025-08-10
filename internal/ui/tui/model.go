package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whynot00/tg-ip-sniffer/internal/models"
	"github.com/whynot00/tg-ip-sniffer/internal/telegram"
)

type packet struct {
	IP, Proto string
	T         time.Time
}

type packetMsg packet
type closedMsg struct{}
type tickMsg time.Time

type ipStat struct {
	count int
	last  time.Time
	proto string
	isTG  bool
}

type Model struct {
	events  <-chan *models.IPRaw
	localIP string
	tgcidr  *telegram.IP
	pick    func(string, string, string) string

	total int

	perIP   map[string]*ipStat
	ipOrder []string

	tgTable    table.Model
	otherTable table.Model
}

func NewModel(events <-chan *models.IPRaw, localIP string, tgcidr *telegram.IP) Model {
	return Model{
		pick:       pickRemote,
		events:     events,
		localIP:    localIP,
		tgcidr:     tgcidr,
		perIP:      make(map[string]*ipStat),
		ipOrder:    make([]string, 0, 64),
		tgTable:    table.New(),
		otherTable: table.New(),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		listenPackets(m.events, m.localIP, m.pick),
		tick(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		w, h := msg.Width, msg.Height
		if w < 20 {
			w = 20
		}
		if h < 10 {
			h = 10
		}
		const chrome = 6
		avail := h - chrome
		if avail < 4 {
			avail = 4
		}
		otherH := avail / 2
		tgH := avail - otherH
		m.otherTable.SetWidth(w)
		m.tgTable.SetWidth(w)
		m.otherTable.SetHeight(otherH)
		m.tgTable.SetHeight(tgH)
		return m, nil

	case packetMsg:
		m.updateStat(msg)
		return m, listenPackets(m.events, m.localIP, m.pick)

	case tickMsg:
		m.RefreshTables()
		return m, tick()

	case closedMsg:
		return m, tea.Quit

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) View() string {
	title := lipgloss.NewStyle().Bold(true).Render(
		fmt.Sprintf("Всего пакетов: %d   Локальный IP: %s", m.total, m.localIP),
	)
	sec := lipgloss.NewStyle().Bold(true)

	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n\n")
	b.WriteString(sec.Render("Иные IP адреса"))
	b.WriteString("\n")
	b.WriteString(m.otherTable.View())
	b.WriteString("\n\n")
	b.WriteString(sec.Render("IP датацентров Telegram"))
	b.WriteString("\n")
	b.WriteString(m.tgTable.View())
	return b.String()
}

func (m *Model) updateStat(p packetMsg) {
	m.total++
	if _, ok := m.perIP[p.IP]; !ok {
		m.ipOrder = append(m.ipOrder, p.IP)
		m.perIP[p.IP] = &ipStat{
			count: 1,
			last:  p.T,
			proto: p.Proto,
			isTG:  m.tgcidr != nil && m.tgcidr.Contains(p.IP),
		}
		return
	}
	st := m.perIP[p.IP]
	st.count++
	st.last = p.T
	st.proto = p.Proto
}

func (m *Model) splitAndSortIPs() (tgIPs, otherIPs []string) {
	for _, ip := range m.ipOrder {
		st := m.perIP[ip]
		if st == nil {
			continue
		}
		if st.isTG {
			tgIPs = append(tgIPs, ip)
		} else {
			otherIPs = append(otherIPs, ip)
		}
	}
	less := func(a, b string) bool {
		sa, sb := m.perIP[a], m.perIP[b]
		if sa.count != sb.count {
			return sa.count > sb.count
		}
		return sa.last.After(sb.last)
	}
	sort.Slice(tgIPs, func(i, j int) bool { return less(tgIPs[i], tgIPs[j]) })
	sort.Slice(otherIPs, func(i, j int) bool { return less(otherIPs[i], otherIPs[j]) })
	return
}

func (m *Model) rowsFromIPs(ips []string) []table.Row {
	rows := make([]table.Row, 0, len(ips))
	for _, ip := range ips {
		if st := m.perIP[ip]; st != nil {
			rows = append(rows, table.Row{
				ip,
				fmt.Sprint(st.count),
				humanSince(st.last),
				st.proto,
			})
		}
	}
	return rows
}

func (m *Model) colWidthsForBoth(tgIPs, otherIPs []string) []int {
	wIP := len("IP")
	wPkts := len("Пакеты")
	wLast := len("только что")
	wProto := len("Протокол")

	check := func(list []string) {
		for _, ip := range list {
			st := m.perIP[ip]
			if st == nil {
				continue
			}
			if l := len(ip); l > wIP {
				wIP = l
			}
			if l := len(fmt.Sprint(st.count)); l > wPkts {
				wPkts = l
			}
			if l := len(humanSince(st.last)); l > wLast {
				wLast = l
			}
			if l := len(st.proto); l > wProto {
				wProto = l
			}
		}
	}
	check(tgIPs)
	check(otherIPs)
	return []int{wIP + 2, wPkts + 2, wLast + 2, wProto + 2}
}

func (m *Model) RefreshTables() {
	tgIPs, otherIPs := m.splitAndSortIPs()
	widths := m.colWidthsForBoth(tgIPs, otherIPs)

	cols := []table.Column{
		{Title: "IP", Width: widths[0]},
		{Title: "Пакеты", Width: widths[1]},
		{Title: "Актив.", Width: widths[2]},
		{Title: "Протокол", Width: widths[3]},
	}
	m.tgTable.SetColumns(cols)
	m.otherTable.SetColumns(cols)
	m.tgTable.SetRows(m.rowsFromIPs(tgIPs))
	m.otherTable.SetRows(m.rowsFromIPs(otherIPs))

	st := table.Styles{
		Header: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			Align(lipgloss.Center),
		Cell: lipgloss.NewStyle().
			Padding(0, 1).
			Align(lipgloss.Left),
	}
	m.tgTable.SetStyles(st)
	m.otherTable.SetStyles(st)
}

func humanSince(t time.Time) string {
	d := time.Since(t)
	if d < time.Second {
		return "только что"
	}
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}

func listenPackets(ch <-chan *models.IPRaw, local string, pick func(src, dst, local string) string) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return closedMsg{}
		}
		if ev == nil {
			return tickMsg(time.Now())
		}
		return packetMsg{
			IP:    pick(ev.IPSrc.String(), ev.IPDst.String(), local),
			Proto: ev.Protocol,
			T:     ev.Time,
		}
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func pickRemote(src, dst, local string) string {
	if src == local {
		return dst
	}
	if dst == local {
		return src
	}
	return dst
}
