package main

import (
  "flag"
  "fmt"
  "net/http"

  "github.com/golang/glog"
  "golang.org/x/net/context"
  "github.com/grpc-ecosystem/grpc-gateway/runtime"
  "google.golang.org/grpc"

  gw "google/cloud/security/iam/playground"
)

var (
  connectPort = flag.Int("grpc-port", 50051, "gRPC port to connect to locally")
  listenPort = flag.Int("http-port", 8081, "http port to listen for incoming connections")
)

func run() error {
  ctx := context.Background()
  ctx, cancel := context.WithCancel(ctx)
  defer cancel()

  connectTo := fmt.Sprintf("localhost:%d", *connectPort)
  listenAt := fmt.Sprintf(":%d", *listenPort)

  mux := runtime.NewServeMux()
  opts := []grpc.DialOption{grpc.WithInsecure()}
  err := gw.RegisterPlaygroundHandlerFromEndpoint(ctx, mux, connectTo, opts)
  if err != nil {
    return err
  }

  return http.ListenAndServe(listenAt, mux)
}

func main() {
  flag.Parse()
  defer glog.Flush()

  for {
    if err := run(); err != nil {
      glog.Fatal(err)
    }
  }
}
