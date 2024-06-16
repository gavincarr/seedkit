module github.com/gavincarr/seedkit

go 1.22.4

replace github.com/gavincarr/go-slip39 => ../go-slip39

require (
	github.com/alecthomas/kong v0.9.0
	github.com/gavincarr/go-slip39 v0.0.1
	github.com/tyler-smith/go-bip39 v1.1.0
)

require (
	github.com/deckarep/golang-set/v2 v2.6.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
)
