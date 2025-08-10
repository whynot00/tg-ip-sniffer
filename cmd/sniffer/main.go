package main

import (
	"context"

	"github.com/whynot00/tg-ip-sniffer/internal/capture"
)

func main() {

	ctx := context.Background()

	reader := capture.NewReader(ctx, "en0")

	go reader.Start(ctx)

}
