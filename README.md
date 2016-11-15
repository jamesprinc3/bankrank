# bankrank-lib

This code was written as part of the WebApps project at the end of 2nd Year. The most complete part is `http/` as this has a full (but basic) scoring mechanism implemented. `dns/` and `email/` (when fully implemented) should work together in order to verify that an email is really from the sender it claims to be from.

In order to use this package you need to have the parent directory (`bankrank/`) located as such:

`xxxxx/Go/src/bankrank`

where xxxxx denotes some path on your system. Then you need to set the $GOPATH environment variable to be `xxxxx/Go/` by e.g.

`export $GOPATH=xxxxx/Go/`

You can then run the tests by invoking `go test bankrank/http` for the http package etc. The main.go file can be run by `go run main.go` 