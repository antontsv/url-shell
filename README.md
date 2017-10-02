# URL shell
Shell script downloader with built-in PGP signature verification.

How many times have you seen instructions to download and install some thing using curl and shell:

`curl -L https://someshellscript.sh | sh` 
(please **don't run this**, I do not own this domain)

Some may even be on clear text `http`.
It is quick and easy to get scripts from web pages and run them in your shell.

This way is convenient, but yet scary, given that HTTP can be intercepted using MITM attack, web servers can be compromised,
company privacy and security policies can change like the hosting provider, etc...

As you have seen many software companies provide checksums and PGP signatures with their software. They expect you to have GPG-suite installed and full keyring be present on every computer you download the software to.

What I am offering here is less convenient, but hopefully more secure way to do `curl | sh`.

As a script author I can produce:
* a script `someshellscript.sh` (again: **don't run this**, I do not own this domain)
* PGP signature `someshellscript.sh.asc`
* Embed my public key into `url-shell`, and do downloads using this script instead of cURL

Given that you distribute your version of `url-shell` in advance, when your users can verify your identity once. They can download your present and future scripts without worrying is beign compromised in between authors development environment and your destination computer. I rely on author to take good care of the PGP private key.

Build your own
==============

To build your own downloader & shell script runner:
* Get your public key:
    `gpg -a --export yourname@youremail.com`
* Paste value in `key.go`
* Compile: `go build -o urlsh .`

Next time you create shell script, and expose it on the Internet, also produce detached signature, and expose it too:
`gpg --detach-sign -a someshellscript.sh`


Result
======
The following:

`curl -s -L https://someshellscript.sh | sh`

can now be replaced with this:

`urlsh https://someshellscript.sh`

given https://someshellscript.sh is original script, and https://someshellscript.sh.asc its detached PGP signature

Yes, it requires end users to get `urlsh` in advance, but gives them piece of mind in a long term.