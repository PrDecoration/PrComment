
//basic Micro service
// go run basic.go
//new terminal -- curl -v -d 'World' localhost:9090
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	//fmt.Println("Hello, World!")
	http.HandleFunc("/", func(rw http.ResponseWriter, rs *http.Request) {
		fmt.Fprintf(rw, "Hello %s", d)
	})
	http.HandleFunc("/goodbye", func(http.ResponseWriter, *http.Request) {
		log.Println("Goodbye World")
	})
	http.ListenAndServe(":9090", nil)
}

func main2() {
	//fmt.Println("Hello, World!")
	http.HandleFunc("/", func(rw http.ResponseWriter, rs *http.Request) {
		d, _ := ioutil.ReadAll(rs.Body)
		fmt.Fprintf(rw, "Hello %s", d)
	})
	http.HandleFunc("/goodbye", func(http.ResponseWriter, *http.Request) {
		log.Println("Goodbye World")
	})
	http.ListenAndServe(":9090", nil)
}
