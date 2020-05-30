package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fasthttp/router"
	cors "github.com/henkman/fasthttpcors"
	"github.com/pkg/profile"
	"github.com/valyala/fasthttp"
)

func main() {
	clean := make(chan os.Signal)
	go func() {
		p := profile.Start(profile.CPUProfile, profile.ProfilePath("."), profile.NoShutdownHook)
		<-clean
		p.Stop()
		os.Exit(0)
	}()
	signal.Notify(clean, os.Kill, os.Interrupt)
	start := time.Now()
	var (
		listen                      string
		services                    map[string]Service
		routeBase                   string
		basicAuth                   BasicAuth
		swaggerResourcesBytes       []byte
		swaggerUIConfigurationBytes []byte
		c                           *cors.CorsHandler
	)
	{
		var config struct {
			Listen                 string                 `json:"listen"`
			RouteBase              string                 `json:"routeBase"`
			BasicAuth              BasicAuth              `json:"basicAuth`
			AllowedOrigins         []string               `json:"allowedOrigins"`
			AllowedMethods         []string               `json:"allowedMethods"`
			AllowedHeaders         []string               `json:"allowedHeaders"`
			Services               map[string]Service     `json:"services"`
			SwaggerUIConfiguration SwaggerUIConfiguration `json:"swaggerUI"`
		}
		cloudConfig := os.Getenv("SPRING_CLOUD_URI")
		if cloudConfig != "" {
			req, err := http.NewRequest("GET", cloudConfig, nil)
			if err != nil {
				panic(err)
			}
			user := os.Getenv("SPRING_CLOUD_USER")
			if user != "" {
				req.SetBasicAuth(user, os.Getenv("SPRING_CLOUD_PASSWORD"))
			}
			cli := http.Client{
				Timeout: 3 * time.Second,
			}
			resp, err := cli.Do(req)
			if err != nil {
				resp.Body.Close()
				panic(err)
			}
			err = json.NewDecoder(resp.Body).Decode(&config)
			resp.Body.Close()
			if err != nil {
				panic(err)
			}
		} else {
			fd, err := os.Open("application.json")
			if err != nil {
				panic(err)
			}
			err = json.NewDecoder(fd).Decode(&config)
			fd.Close()
			if err != nil {
				panic(err)
			}
		}

		swaggerResources := make([]SwaggerResource, 0, len(config.Services))
		for serviceName, _ := range config.Services {
			u := fmt.Sprintf("%s%s/v2/api-docs", config.RouteBase, serviceName)
			swaggerResources = append(swaggerResources, SwaggerResource{
				Name:           serviceName,
				URL:            u,
				SwaggerVersion: "2.0",
				Location:       u,
			})
		}
		{
			raw, err := json.Marshal(swaggerResources)
			if err != nil {
				panic(err)
			}
			swaggerResourcesBytes = raw
		}

		{
			raw, err := json.Marshal(config.SwaggerUIConfiguration)
			if err != nil {
				panic(err)
			}
			swaggerUIConfigurationBytes = raw
		}
		listen = config.Listen
		routeBase = config.RouteBase
		services = config.Services
		basicAuth = config.BasicAuth

		c = cors.NewCorsHandler(cors.Options{
			AllowedOrigins:   config.AllowedOrigins,
			AllowedMethods:   config.AllowedMethods,
			AllowedHeaders:   config.AllowedHeaders,
			AllowCredentials: true,
			Debug:            true,
		})
	}
	mux := router.New()
	mux.GET("/swagger-resources",
		func(ctx *fasthttp.RequestCtx) {
			if !basicAuth.IsAuthorized(&ctx.Request) {
				ctx.Response.Header.Set(
					fasthttp.HeaderWWWAuthenticate, `Basic realm="Restricted"`)
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				return
			}
			ctx.Response.Header.Set(
				fasthttp.HeaderContentType, "application/json")
			ctx.SetBody(swaggerResourcesBytes)
		})
	mux.GET("/swagger-resources/configuration/ui",
		func(ctx *fasthttp.RequestCtx) {
			if !basicAuth.IsAuthorized(&ctx.Request) {
				ctx.Response.Header.Set(
					fasthttp.HeaderWWWAuthenticate, `Basic realm="Restricted"`)
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				return
			}
			ctx.Response.Header.Set(
				fasthttp.HeaderContentType, "application/json")
			ctx.SetBody(swaggerUIConfigurationBytes)
		})
	mux.GET("/swagger-resources/configuration/security",
		func(ctx *fasthttp.RequestCtx) {
			if !basicAuth.IsAuthorized(&ctx.Request) {
				ctx.Response.Header.Set(
					fasthttp.HeaderWWWAuthenticate, `Basic realm="Restricted"`)
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				return
			}
			ctx.Response.Header.Set(
				fasthttp.HeaderContentType, "application/json")
			ctx.SetBodyString("{}")
		})
	mux.GET("/swagger-ui.html",
		func(ctx *fasthttp.RequestCtx) {
			if !basicAuth.IsAuthorized(&ctx.Request) {
				ctx.Response.Header.Set(
					fasthttp.HeaderWWWAuthenticate, `Basic realm="Restricted"`)
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				return
			}
			ctx.Response.Header.Set(
				fasthttp.HeaderContentType, "text/html")
			ctx.SendFile("swagger-ui.html")
		})
	mux.ServeFiles("/swagger-ui-resources/{filepath:*}",
		"./swagger-ui-resources")
	for name, service := range services {
		ep := routeBase + name
		proxy := MakePrefixedReverseProxy(len(ep), service.Url)
		mux.ANY(ep+"/{path:*}", proxy.Handler)
	}
	lh := LoggingHandler{Next: c.CorsMiddleware(mux.Handler)}
	server := fasthttp.Server{
		NoDefaultServerHeader: true,
		NoDefaultContentType:  true,
		NoDefaultDate:         true,
		Handler:               lh.Handler,
	}
	log.Println("started in", time.Since(start), "and listening at", listen)
	if err := server.ListenAndServe(listen); err != nil {
		log.Fatal(err)
	}
}

type LoggingHandler struct {
	Next fasthttp.RequestHandler
}

func (lh *LoggingHandler) Handler(ctx *fasthttp.RequestCtx) {
	fmt.Println(string(ctx.Method()), ctx.Request.URI())
	ctx.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		value := string(v)
		fmt.Println(key, value)
	})
	fmt.Println("++++")
	lh.Next(ctx)
	ctx.Response.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		value := string(v)
		fmt.Println(key, value)
	})
	fmt.Println("####")
}

type SwaggerResource struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	SwaggerVersion string `json:"swaggerVersion"`
	Location       string `json:"location"`
}

type SwaggerUIConfiguration struct {
	DeepLinking              bool     `json:"deepLinking"`
	DisplayOperationID       bool     `json:"displayOperationId"`
	DefaultModelsExpandDepth int      `json:"defaultModelsExpandDepth"`
	DefaultModelExpandDepth  int      `json:"defaultModelExpandDepth"`
	DefaultModelRendering    string   `json:"defaultModelRendering"`
	DisplayRequestDuration   bool     `json:"displayRequestDuration"`
	DocExpansion             string   `json:"docExpansion"`
	Filter                   bool     `json:"filter"`
	OperationsSorter         string   `json:"operationsSorter"`
	ShowExtensions           bool     `json:"showExtensions"`
	TagsSorter               string   `json:"tagsSorter"`
	ValidatorURL             string   `json:"validatorUrl"`
	ApisSorter               string   `json:"apisSorter"`
	JSONEditor               bool     `json:"jsonEditor"`
	ShowRequestHeaders       bool     `json:"showRequestHeaders"`
	SupportedSubmitMethods   []string `json:"supportedSubmitMethods"`
}

type BasicAuth struct {
	Credentials
}

func (ba *BasicAuth) IsAuthorized(r *fasthttp.Request) bool {
	auth := r.Header.Peek(fasthttp.HeaderAuthorization)
	if len(auth) < 6 || !bytes.Equal(bytes.ToLower(auth[:5]), []byte("basic")) {
		return false
	}
	b64 := auth[6:]
	enc := base64.StdEncoding
	dbuf := make([]byte, enc.DecodedLen(len(b64)))
	n, err := enc.Decode(dbuf, b64)
	if err == nil {
		cred := string(dbuf[:n])
		colon := strings.IndexByte(cred, ':')
		if ba.Username == cred[:colon] && ba.Password == cred[colon+1:] {
			return true
		}
	}
	return false
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Service struct {
	Url string `json:"url"`
}

type PrefixedReverseProxy struct {
	prefixLength int
	client       fasthttp.HostClient
}

func MakePrefixedReverseProxy(prefixLength int, target string) PrefixedReverseProxy {
	return PrefixedReverseProxy{
		prefixLength: prefixLength,
		client:       fasthttp.HostClient{Addr: target},
	}
}

func (proxy PrefixedReverseProxy) Handler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	if host, _, err := net.SplitHostPort(ctx.RemoteAddr().String()); err == nil {
		req.Header.Add("X-Forwarded-For", host)
	}
	reqUri := req.RequestURI()
	req.Header.AddBytesV("X-Forwarded-Prefix", reqUri[:proxy.prefixLength])
	req.SetRequestURIBytes(reqUri[proxy.prefixLength:])
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	res := &ctx.Response
	resHeaders := make(map[string]string)
	res.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		value := string(v)
		if val, ok := resHeaders[key]; ok {
			resHeaders[key] = val + "," + value
		}
		resHeaders[key] = value
	})
	if err := proxy.client.Do(req, res); err != nil {
		res.SetStatusCode(fasthttp.StatusBadGateway)
	}
	for _, h := range hopHeaders {
		res.Header.Del(h)
	}
	for k, v := range resHeaders {
		res.Header.Set(k, v)
	}
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}
