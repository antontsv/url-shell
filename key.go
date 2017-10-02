package main

/*
This should hold a value of your public key,
later on it will be used to verify that certain scripts you created
in the past and that were signed using private key, are still
valid when you download them.

You can get your key using this command:
gpg -a --export yourname@youremail.com

Node value will start with:
-----BEGIN PGP PUBLIC KEY BLOCK-----
and end with:
-----END PGP PUBLIC KEY BLOCK-----

*/
var publicKey = ``
