package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"github.com/rs/cors"
)

func main() {
	start := time.Now()
	var (
		listen                      string
		services                    map[string]Service
		routeBase                   string
		basicAuth                   BasicAuth
		swaggerResourcesBytes       []byte
		swaggerUIConfigurationBytes []byte
		c                           *cors.Cors
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

		c = cors.New(cors.Options{
			AllowedOrigins:   config.AllowedOrigins,
			AllowedMethods:   config.AllowedMethods,
			AllowedHeaders:   config.AllowedHeaders,
			AllowCredentials: true,
			Debug:            false,
		})
	}

	var mux http.ServeMux
	mux.HandleFunc("/swagger-resources", func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write(swaggerResourcesBytes)
	})
	mux.HandleFunc("/swagger-resources/configuration/ui", func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write(swaggerUIConfigurationBytes)
	})
	mux.HandleFunc("/swagger-resources/configuration/security", func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/swagger-ui.html", func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth.IsAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "text/html")
		http.ServeFile(w, r, "swagger-ui.html")
	})
	mux.Handle("/swagger-ui-resources/",
		http.StripPrefix("/swagger-ui-resources",
			http.FileServer(http.Dir("./swagger-ui-resources"))))
	var buffers Buffers
	for name, service := range services {
		serviceBase := routeBase + name
		mux.Handle(serviceBase+"/", reverseProxy(serviceBase, service.Url, &buffers))
	}
	log.Println("started in", time.Since(start), "and listening at", listen)
	if err := http.ListenAndServe(listen, c.Handler(&mux)); err != nil {
		panic(err)
	}
}

type Buffers struct {
	pool sync.Pool
}

func (bs *Buffers) Get() []byte {
	if b := bs.pool.Get(); b != nil {
		return b.([]byte)
	}
	return make([]byte, 32*1024)
}

func (bs *Buffers) Put(b []byte) {
	bs.pool.Put(b)
}

func reverseProxy(serviceBase, url string, buffers httputil.BufferPool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{Director: func(r *http.Request) {
		r.Header.Set("X-Forwarded-Prefix", serviceBase)
		r.URL.Path = r.URL.Path[len(serviceBase):]
		r.URL.Host = url
		r.URL.Scheme = "http"
	}, BufferPool: buffers}
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

func (ba *BasicAuth) IsAuthorized(r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	return ok && ba.Username == username && ba.Password == password
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Service struct {
	Url string `json:"url"`
}
