package models

import (
	"net"
	"time"
)

type IPRaw struct {
	Time     time.Time
	IPSrc    net.IP
	IPDst    net.IP
	Protocol string
}
