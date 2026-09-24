package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kangheeyong/authgate/internal/app"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := checkHealth(context.Background(), os.Getenv("PORT")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	app.Run()
}
