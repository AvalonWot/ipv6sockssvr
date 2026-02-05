package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	listenAddr := flag.String("l", ":10808", "listen address & port")
	prefix := flag.String("p", "", "ipv6 prefix")
	flag.Parse()

	if prefix == nil {
		log.Fatalf("no ipv6 prefix, use -p set")
	}

	// Ensure only one instance is running
	if err := ensureSingleInstance(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
	defer cleanupPidFile()

	srv, err := NewServer(*listenAddr, *prefix)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("server is downing...")
		srv.Shutdown()
	}()

	srv.ListenAndServe()
}
