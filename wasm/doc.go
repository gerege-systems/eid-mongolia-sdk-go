//go:build !(js && wasm)

// Command wasm — pades-ийн WebAssembly entrypoint (GOOS=js GOARCH=wasm); main.go-г үз. Бусад платформд хоосон.
package main

func main() {}
