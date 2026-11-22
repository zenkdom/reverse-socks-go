package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"reverse-socks/pkg/admin"
	"reverse-socks/pkg/control"
	"reverse-socks/pkg/mtproto"
	"reverse-socks/pkg/proxy"
	"reverse-socks/pkg/users"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to config.json")
	socksHost := flag.String("socks-host", "", "SOCKS5 bind host")
	socksPort := flag.Int("socks-port", 0, "SOCKS5 bind port")
	mtprotoPort := flag.Int("mtproto-port", 0, "MTProto bind port")
	mtprotoSecret := flag.String("mtproto-secret", "", "MTProto secret (hex)")
	mtprotoDomain := flag.String("mtproto-domain", "", "Fake-TLS mask domain")
	mtprotoTag := flag.String("mtproto-tag", "", "MTProto promo channel TAG")
	controlHost := flag.String("control-host", "", "Control bridge bind host")
	controlPort := flag.Int("control-port", 0, "Control bridge bind port")
	adminHost := flag.String("admin-host", "", "Admin panel bind host")
	adminPort := flag.Int("admin-port", 0, "Admin panel bind port")
	adminUser := flag.String("admin-user", "", "Admin username")
	adminPass := flag.String("admin-pass", "", "Admin password")
	secretToken := flag.String("token", "", "Secret token for reverse agents")
	strategy := flag.String("strategy", "", "Load balance strategy (rotation, round_robin, random, sticky)")
	failoverTimeout := flag.Float64("failover-timeout", 0, "Failover timeout in seconds")
	connectTimeout := flag.Float64("connect-timeout", 0, "Target connection timeout in seconds")
	logLevel := flag.String("log-level", "", "Logging level (DEBUG, INFO, WARN, ERROR, QUIET)")
	flag.Parse()

	cfg, _ := control.LoadConfig(*configPath)

	effLogLevel := cfg.LogLevel
	if *logLevel != "" {
		effLogLevel = *logLevel
	}

	if strings.EqualFold(effLogLevel, "ERROR") || strings.EqualFold(effLogLevel, "QUIET") || strings.EqualFold(effLogLevel, "NONE") {
		log.SetOutput(io.Discard)
	}

	sHost := cfg.Socks5.Host
	if *socksHost != "" {
		sHost = *socksHost
	}
	sPort := cfg.Socks5.Port
	if *socksPort > 0 {
		sPort = *socksPort
	}

	mEnabled := cfg.MTProto.Enabled
	mHost := cfg.MTProto.Host
	mPort := cfg.MTProto.Port
	if *mtprotoPort > 0 {
		mPort = *mtprotoPort
	}
	mSecret := cfg.MTProto.Secret
	if *mtprotoSecret != "" {
		mSecret = *mtprotoSecret
	}
	mDomain := cfg.MTProto.Domain
	if *mtprotoDomain != "" {
		mDomain = *mtprotoDomain
	}
	mTag := cfg.MTProto.Tag
	if *mtprotoTag != "" {
		mTag = *mtprotoTag
	}
	mMaskHost := cfg.MTProto.MaskHost
	mMaskPort := cfg.MTProto.MaskPort

	cHost := cfg.Control.Host
	if *controlHost != "" {
		cHost = *controlHost
	}
	cPort := cfg.Control.Port
	if *controlPort > 0 {
		cPort = *controlPort
	}
	cToken := cfg.Control.SecretToken
	if *secretToken != "" {
		cToken = *secretToken
	}

	aHost := cfg.Admin.Host
	if *adminHost != "" {
		aHost = *adminHost
	}
	aPort := cfg.Admin.Port
	if *adminPort > 0 {
		aPort = *adminPort
	}
	aUser := cfg.Admin.Username
	if *adminUser != "" {
		aUser = *adminUser
	}
	aPass := cfg.Admin.Password
	if *adminPass != "" {
		aPass = *adminPass
	}

	balStrat := cfg.BalanceStrategy
	if *strategy != "" {
		balStrat = *strategy
	}
	foSec := cfg.FastFailoverSeconds
	if *failoverTimeout > 0 {
		foSec = *failoverTimeout
	}
	connSec := cfg.ConnectTimeout
	if *connectTimeout > 0 {
		connSec = *connectTimeout
	}

	log.Println("============================================================")
	log.Println("   REVERSE SOCKS5 & MTPROTO CONTROL SERVER (GO HIGH-SPEED)")
	log.Printf("   SOCKS5 Service:    %s:%d (Auth: REQUIRED)", sHost, sPort)
	if mEnabled {
		tagInfo := ""
		if mTag != "" {
			tagInfo = fmt.Sprintf(", TAG: %s", mTag)
		}
		log.Printf("   MTProto Fake-TLS:  %s:%d (Domain: %s%s)", mHost, mPort, mDomain, tagInfo)
	}
	log.Printf("   Control Bridge:    %s:%d", cHost, cPort)
	log.Printf("   Admin Web Panel:   http://%s:%d (User: %s)", aHost, aPort, aUser)
	log.Printf("   Balance Strategy:  %s (Failover: %.1fs)", balStrat, foSec)
	log.Println("============================================================")

	agentManager := control.NewAgentManager(balStrat, time.Duration(foSec*float64(time.Second)))
	userManager := users.NewUserManager("users.json")

	var mtprotoUserManager *users.MtprotoUserManager
	if mEnabled {
		mtprotoUserManager = users.NewMtprotoUserManager("mtproto_users.json", mSecret, mDomain, mTag)
	}

	controlServer := control.NewControlBridgeServer(agentManager, cHost, cPort, cToken)
	if err := controlServer.Start(); err != nil {
		log.Fatalf("Failed starting Control Bridge: %v", err)
	}
	defer controlServer.Stop()

	proxyServer := proxy.NewUniversalProxyServer(
		agentManager,
		userManager,
		sHost,
		sPort,
		time.Duration(foSec*float64(time.Second)),
		time.Duration(connSec*float64(time.Second)),
	)
	if err := proxyServer.Start(); err != nil {
		log.Fatalf("Failed starting Universal Proxy: %v", err)
	}
	defer proxyServer.Stop()

	var mtprotoServer *mtproto.MtprotoProxyServer
	if mEnabled {
		mtprotoServer = mtproto.NewMtprotoProxyServer(
			agentManager,
			mtprotoUserManager,
			mHost,
			mPort,
			mSecret,
			mDomain,
			mTag,
			mMaskHost,
			mMaskPort,
			time.Duration(foSec*float64(time.Second)),
			time.Duration(connSec*float64(time.Second)),
		)
		if err := mtprotoServer.Start(); err != nil {
			log.Fatalf("Failed starting MTProto Proxy: %v", err)
		}
		defer mtprotoServer.Stop()
	}

	fakeTLSSecret := ""
	if mtprotoServer != nil {
		fakeTLSSecret = mtprotoServer.FakeTLSSecret()
	}

	adminServer := admin.NewWebServer(
		agentManager,
		userManager,
		mtprotoUserManager,
		aHost,
		aPort,
		aUser,
		aPass,
		sPort,
		mPort,
		fakeTLSSecret,
		mDomain,
		mTag,
	)
	if err := adminServer.Start(); err != nil {
		log.Fatalf("Failed starting Admin Web Panel: %v", err)
	}
	defer func() {
		_ = adminServer.Stop()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutdown signal received, terminating all services gracefully...")
}
