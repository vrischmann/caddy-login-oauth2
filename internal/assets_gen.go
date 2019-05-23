// +build ignore

package main

import (
	"log"
	"net/http"

	"github.com/shurcooL/vfsgen"
)

func main() {
	opts := vfsgen.Options{
		PackageName:  "internal",
		BuildTags:    "!dev",
		VariableName: "Assets",
	}

	err := vfsgen.Generate(http.Dir("assets"), opts)
	if err != nil {
		log.Fatal(err)
	}
}
