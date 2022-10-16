package main

import (
    "crypto/tls"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
)

func main() {
    // TODO: Load client cert from CNG instead of file
    certificate, err := tls.LoadX509KeyPair("../TestCertificates/ClientCert.pem", "../TestCertificates/ClientCert.pem")
    if err != nil {
        log.Fatalf("could not load certificate: %v", err)
    }

    client := http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                Certificates: []tls.Certificate{certificate},
            },
        },
    }

    resp,err := client.Get("https://localhost")
    if err != nil {
        log.Fatalf("error making get request: %v", err)
    }

    body,err := ioutil.ReadAll(resp.Body)
    if err != nil{
        log.Fatalf("error reading response: %v", err)
    }
    fmt.Println(string(body))
}
