package main

import (
    "crypto/tls"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "github.com/google/certtostore"
)

func main() {
    store, err := certtostore.OpenWinCertStore(certtostore.ProviderMSSoftware, "te-26518e73-dc6d-4917-8516-69e714602cba", nil, nil, false)
    if err != nil {
        log.Fatalf("OpenWinCertStore error: %v", err)
    }
    fmt.Println("Provider: "+store.ProvName)
    
    err = store.Link()
    if err != nil {
        log.Fatalf("Link error: %v", err)
    }
    
    cred, err := store.Key()
    if err != nil {
        log.Fatalf("Key error: %v", err)
    }

    pKey := cred.Public()
    fmt.Printf("Public key: %v\n", pKey)

    //cert, context, err := store.CertWithContext()
    //if err != nil {
    //    log.Fatalf("CertWithContext error: %v", err)
    //}
    //fmt.Println("Certificate: %v", cert) // nullptr

    //key, err := store.CertKey(context)
    //if err != nil {
    //    log.Fatalf("CertKey error (private key not found): %v", err)
    //}
    //fmt.Printf("find cert '%s' with private key in container '%s', algo '%s'\n", cert.Subject, key.Container, key.AlgorithmGroup)

    //cert, err := store.Cert()
    //if err != nil {
    //    log.Fatalf("Cert error: %v", err)
    //}
    //fmt.Println("Subject: %v", cert) // nullptr

    // TODO: Load client cert from CNG instead of file
    cert, err := tls.LoadX509KeyPair("../TestCertificates/ClientCert.pem", "../TestCertificates/ClientCert.pem")
    if err != nil {
        log.Fatalf("could not load certificate: %v", err)
    }

    client := http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                Certificates: []tls.Certificate{cert},
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
