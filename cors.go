package CORS

import (
	"strconv"
	"strings"
	"unsafe"

	"github.com/valyala/fasthttp"
)

type (
	CORSConfiguration struct {
		Origins          []string  `json:"origins"`
		ExposeHeaders    *[]string `json:"expose_headers"`
		AllowMethods     *[]string `json:"allow_methods"`
		AllowHeaders     *[]string `json:"allow_headers"`
		AllowCredentials *bool     `json:"allow_credentials"`
		MaxAge           *int      `json:"max_age"`
	}

	innerCORS struct {
		origin func(header *fasthttp.ResponseHeader) bool
		header [][2]string
	}
)

func Prepare(configuration CORSConfiguration) innerCORS {
	CORS := innerCORS{header: make([][2]string, 0, 5)}

	if len(configuration.Origins) == 0 {
		CORS.origin = func(header *fasthttp.ResponseHeader) bool {
			header.Set(fasthttp.HeaderAccessControlAllowOrigin, "*")
			return true
		}
	} else {
		origins := make([]string, 0, (len(configuration.Origins) * 2))

		for _, value := range configuration.Origins {
			origins = append(origins, ("http://" + value), ("https://" + value))
		}

		CORS.origin = func(header *fasthttp.ResponseHeader) bool {
			origin := header.Peek(fasthttp.HeaderOrigin)
			originString := unsafe.String(unsafe.SliceData(origin), len(origin))

			for _, value := range origins {
				if value == originString {
					header.Set(fasthttp.HeaderAccessControlAllowOrigin, originString)
					return true
				}
			}

			return false
		}
	}

	if configuration.ExposeHeaders != nil {
		exposeHeaders := strings.Join(*configuration.ExposeHeaders, ", ")
		CORS.header = append(CORS.header, [2]string{fasthttp.HeaderAccessControlExposeHeaders, exposeHeaders})
	}

	if configuration.AllowMethods != nil {
		allowMethods := strings.Join(*configuration.AllowMethods, ", ")
		CORS.header = append(CORS.header, [2]string{fasthttp.HeaderAccessControlAllowMethods, allowMethods})
	}

	if configuration.AllowHeaders != nil {
		allowHeaders := strings.Join(*configuration.AllowHeaders, ", ")
		CORS.header = append(CORS.header, [2]string{fasthttp.HeaderAccessControlAllowHeaders, allowHeaders})
	}

	if configuration.AllowCredentials != nil {
		allowCredentials := "false"

		if *configuration.AllowCredentials {
			allowCredentials = "true"
		}

		CORS.header = append(CORS.header, [2]string{fasthttp.HeaderAccessControlAllowCredentials, allowCredentials})
	}

	if configuration.MaxAge != nil {
		maxAge := strconv.Itoa(*configuration.MaxAge)
		CORS.header = append(CORS.header, [2]string{fasthttp.HeaderAccessControlMaxAge, maxAge})
	}

	return CORS
}

func (CORS innerCORS) Handler(source fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		header := &ctx.Response.Header

		origin := CORS.origin(header)
		if !origin {
			return
		}

		for _, value := range CORS.header {
			header.Set(value[0], value[1])
		}

		source(ctx)
	}
}
