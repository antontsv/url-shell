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
	"strings"

	"github.com/kardianos/osext"
	"golang.org/x/crypto/openpgp"
)

func main() {

	maxbytes := flag.Int64("max_bytes", 1048576, "Max number of bytes to download. Used to prevent unexpectedly large downloads")
	surl := flag.String("sig_url", "", "URL for detached PGP signature file. Default is source URL with .asc appended at the end")
	showsigner := flag.Bool("show_signer", false, "Show the name of a signer for the URL")
	execute := flag.Bool("do_exec", true, "Execute downloaded content in bash")

	flag.Parse()

	url := flag.Arg(0)
	if *surl == "" {
		*surl = url + ".asc"
	}

	if len(publicKey) <= 0 {
		log.Fatal("No public key was set during script compile time")
	}

	type Download struct {
		resType string
		resp    *http.Response
	}

	downloadc := make(chan Download)
	downloader := func(name string, url string) {
		resp, err := http.Get(url)
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Fatalf("Could not download %s from %s\n", name, url)
		}
		downloadc <- Download{resType: name, resp: resp}
	}

	const (
		resContent = "content"
		resSig     = "signature"
	)

	go downloader(resContent, url)
	go downloader(resSig, *surl)

	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKey))
	if err != nil {
		log.Fatalf("embedded key is bad: %v\n", err)
	}

	downloads := make(map[string]*http.Response)

	for i := 0; i < 2; i++ {
		d := <-downloadc
		downloads[d.resType] = d.resp
	}
	close(downloadc)
	defer downloads[resContent].Body.Close()
	defer downloads[resSig].Body.Close()

	var buf bytes.Buffer
	tee := io.TeeReader(io.LimitReader(downloads[resContent].Body, *maxbytes), &buf)

	entity, err := openpgp.CheckArmoredDetachedSignature(keyring, tee, downloads[resSig].Body)
	if err != nil {
		log.Fatalf("file and signature mismatch: %v\n", err)
		return
	}

	if *showsigner {
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

	script := tostring(&buf)

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
		cmd := exec.CommandContext(context.Background(), "/usr/bin/env", "bash", "-c", script)
		b, err := cmd.Output()
		fmt.Println(string(b))
		if err != nil {
			log.Fatalf("shell script has exited with an error: %v\n", err)
		}
	}

}
