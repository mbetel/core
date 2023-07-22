module core

go 1.20

require (
	github.com/go-sql-driver/mysql v1.7.1
	github.com/gorilla/csrf v1.7.1
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.2.1
	github.com/husobee/vestigo v1.1.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/justinas/alice v1.2.0
	github.com/mbetel/core v0.0.0-20190909111224-736f1f1d4dd8
	golang.org/x/crypto v0.11.0
)

require (
	github.com/lib/pq v1.10.9 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
)

replace core => github.com/mbetel/core v0.0.0-20230722130251-4d6983e07dc0
