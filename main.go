package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/kardianos/osext"
	"golang.org/x/crypto/openpgp"
)

type download struct {
	resType string
	resp    *http.Response
}

func main() {

	maxbytes := flag.Int64("max_bytes", 1048576, "Max number of bytes to download. Used to prevent unexpectedly large downloads")
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

	downloadAndExec(url, *surl, *showsigner, *execute, *maxbytes, *maxdownload, *maxexecution)

}

func downloadAndExec(url string, sigurl string, showsig bool, doexec bool, maxbytes int64, maxdown, maxexec time.Duration) {

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	signl := make(chan os.Signal)
	signal.Notify(signl, os.Interrupt)
	go func() {
		s := <-signl
		fmt.Fprintf(os.Stderr, "Got signal: %v, canceling processes in flight...\n", s)
		mainCancel()
	}()

	downloadc := make(chan download)
	downloader := func(name string, url string) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		ctx, cancel := context.WithTimeout(mainCtx, maxdown)
		defer cancel()
		req = req.WithContext(ctx)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if err == nil {
				err = fmt.Errorf("unexpected HTTP response code %d", resp.StatusCode)
			}
			log.Fatalf("Could not download %s from %s: %v\n", name, url, err)
		}
		downloadc <- download{resType: name, resp: resp}
	}

	const (
		resContent = "content"
		resSig     = "signature"
	)

	go downloader(resContent, url)
	go downloader(resSig, sigurl)

	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKey))
	if err != nil {
		log.Fatalf("embedded key is bad: %v\n", err)
	}

	downloads := make(map[string]*http.Response)

	for i := 0; i < 2; i++ {
		d, ok := <-downloadc
		if !ok {
			log.Fatal("did not receive necessary downloads")
		}
		downloads[d.resType] = d.resp
	}

	defer downloads[resContent].Body.Close()
	defer downloads[resSig].Body.Close()

	var buf bytes.Buffer
	tee := io.TeeReader(io.LimitReader(downloads[resContent].Body, maxbytes), &buf)

	entity, err := openpgp.CheckArmoredDetachedSignature(keyring, tee, downloads[resSig].Body)
	if err != nil {
		log.Fatalf("file and signature mismatch: %v\n", err)
		return
	}

	if showsig {
		for _, v := range entity.Identities {
			fmt.Printf("Downloaded content was signed by: %v\n", v.UserId.Name)
		}
	}

	tostring := func(r io.Reader) string {
		b, err := ioutil.ReadAll(r)
		if err != nil {
			log.Fatal(err)
		}

		return string(b)
	}

	if doexec {
		script := tostring(&buf)
		execName, err := osext.Executable()
		if err != nil {
			log.Fatal("Cannot get full path of the current program")
		}
		envname := "URL_SHELL_EXEC"
		err = os.Setenv(envname, execName)
		if err != nil {
			log.Fatalf("should not set env var %s: %v\n", envname, err)
		}
		ctx, cancel := context.WithTimeout(mainCtx, maxexec)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/env", "bash", "-c", script)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		if err != nil {
			log.Fatalf("shell script has exited with an error: %v\n", err)
		}
	}

}
