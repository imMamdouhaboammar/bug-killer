module example.com/fixture-app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.21.0 // indirect
)

require github.com/stretchr/testify v1.8.4

replace example.com/old/mod => example.com/new/mod v1.2.0
