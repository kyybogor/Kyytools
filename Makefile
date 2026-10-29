BINARY_NAME=kyytools
CMD_DIR=./cmd/kyytools

.PHONY: all build test fmt vet clean run help

all: fmt vet test build

build:
	go build -o $(BINARY_NAME) $(CMD_DIR)

build-windows:
	go build -o $(BINARY_NAME).exe $(CMD_DIR)

test:
	go test -v ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	go clean
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe

run: build
	./$(BINARY_NAME)

help:
	@echo "Perintah yang tersedia:"
	@echo "  make build         - Kompilasi binary"
	@echo "  make build-windows - Kompilasi binary untuk Windows (.exe)"
	@echo "  make test          - Jalankan seluruh unit test"
	@echo "  make fmt           - Format kode dengan go fmt"
	@echo "  make vet           - Analisis kode dengan go vet"
	@echo "  make clean         - Bersihkan artefak binary"
