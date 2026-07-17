// Separate module on purpose: keeps this deliberately-vulnerable code out of the
// root module's build, vet, and tests. It exists only to be scanned.
module example.com/vulnerable-demo

go 1.24
