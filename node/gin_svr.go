package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data"
	"source.quilibrium.com/quilibrium/monorepo/node/tlsutils"
)

var lastMaxFrame = uint64(0)
var lastBalance = float64(0)

func InitGin(ginPort string, cfg *config.Config) {
	engine := gin.Default()
	// Use gzip middleware
	engine.Use(gzip.Gzip(gzip.DefaultCompression))

	engine.GET("/task", func(ctx *gin.Context) {
		data.MGetTask(ctx, cfg)
	})
	engine.POST("/task", func(ctx *gin.Context) {
		data.PostResult(ctx, cfg)
	})

	go func() {
		if err := engine.Run(fmt.Sprintf(":%s", ginPort)); err != nil {
			log.Fatal(err.Error())
		}
	}()

}

func InitQuicServer(quicPort string, cfg *config.Config) {
	mux := http.NewServeMux()
	engine := gin.Default()
	// Use gzip middleware
	engine.Use(gzip.Gzip(gzip.DefaultCompression))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		engine.ServeHTTP(w, r)
	})

	engine.GET("/task", func(ctx *gin.Context) {
		data.MGetTask(ctx, cfg)
	})
	engine.POST("/task", func(ctx *gin.Context) {
		data.PostResult(ctx, cfg)
	})

	server := http3.Server{
		Handler:   mux,
		Addr:      fmt.Sprintf(":%s", quicPort),
		TLSConfig: tlsutils.GetTLSConfig(),
		QUICConfig: &quic.Config{
			Allow0RTT: true,
		},
	}

	go server.ListenAndServe()
}
