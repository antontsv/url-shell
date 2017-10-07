package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/antontsv/sigdown"
	"github.com/kardianos/osext"
)

func main() {

	maxbytes := flag.Int("max_bytes", 1048576, "Max number of bytes to download. Used to prevent unexpectedly large downloads")
	surl := flag.String("sig_url", "", "URL for detached PGP signature file. Default is source URL with .asc appended at the end")
	showsigner := flag.Bool("show_signer", false, "Show the name of a signer for the URL")
	execute := flag.Bool("do_exec", true, "Execute downloaded content in bash")
	maxdownload := flag.Duration("max_download_time", 60*time.Second, "Max time interval to attempt download")
	maxexecution := flag.Duration("max_exec_time", 10*time.Minute, "Max time interval to execute script")

	flag.Parse()

	url := flag.Arg(0)
	if *surl == "" {
		*surl = url + ".asc"
	}

	if len(publicKey) <= 0 {
		log.Fatal("No public key was set during script compile time")
	}

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	signl := make(chan os.Signal)
	signal.Notify(signl, os.Interrupt)
	go func() {
		s := <-signl
		fmt.Fprintf(os.Stderr, "Got signal: %v, canceling processes in flight...\n", s)
		mainCancel()
	}()

	downloader, err := sigdown.New(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	downloader.MaxBytes = *maxbytes
	downloader.MaxTime = *maxdownload
	download, err := downloader.Download(mainCtx, url, *surl)
	if err != nil {
		log.Fatal(err)
	}

	if *showsigner {
		for _, name := range download.Signers {
			fmt.Printf("Downloaded content was signed by: %s\n", name)
		}
	}

	if *execute {
		execName, err := osext.Executable()
		if err != nil {
			log.Fatal("Cannot get full path of the current program")
		}
		envname := "URL_SHELL_EXEC"
		err = os.Setenv(envname, execName)
		if err != nil {
			log.Fatalf("should not set env var %s: %v\n", envname, err)
		}
		ctx, cancel := context.WithTimeout(mainCtx, *maxexecution)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/env", "bash", "-c", download.Content)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		if err != nil {
			log.Fatalf("shell script has exited with an error: %v\n", err)
		}
	}

}
