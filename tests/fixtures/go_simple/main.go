package main

import (
	"fmt"

	_ "github.com/lib/pq" // side-effect driver registration — must stay IN_USE
)

func main() {
	fmt.Println("ok")
}
