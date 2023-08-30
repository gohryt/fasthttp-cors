package middlewares

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/valyala/fasthttp"
)

type (
	CORSConfiguration struct {
		Origins, Methods, Headers []string
	}

	innerCORS struct {
		origins, methods, headers []string
	}
)

var ErrCORSOriginNotFound = errors.New("origin not found")

func CORS(configuration CORSConfiguration) *innerCORS {
	CORS := &innerCORS{
		methods: configuration.Methods,
		headers: configuration.Headers,
	}

	for i := range configuration.Origins {
		CORS.origins = append(CORS.origins, ("http://" + configuration.Origins[i]), ("https://" + configuration.Origins[i]))
	}

	return CORS
}

func (CORS *innerCORS) Handler(source fasthttp.RequestHandler) fasthttp.RequestHandler {
	methods := "*"

	if len(CORS.methods) > 0 {
		methods = strings.Join(CORS.methods, ",")
	}

	headers := "*"

	if len(CORS.headers) > 0 {
		headers = strings.Join(CORS.headers, ",")
	}

	if CORS.origins == nil {
		return func(context *fasthttp.RequestCtx) {
			header := &context.Response.Header

			header.Set(fasthttp.HeaderAccessControlAllowOrigin, "*")
			header.Set(fasthttp.HeaderAccessControlAllowMethods, methods)
			header.Set(fasthttp.HeaderAccessControlAllowHeaders, headers)

			if source != nil {
				source(context)
			}
		}
	}

	return func(context *fasthttp.RequestCtx) {
		header := &context.Response.Header

		origin := context.Request.Header.Peek(fasthttp.HeaderOrigin)
		originString := unsafe.String(unsafe.SliceData(origin), len(origin))

		found := false

		for i := range CORS.origins {
			found = CORS.origins[i] == originString

			if found != false {
				header.Set(fasthttp.HeaderAccessControlAllowOrigin, originString)
				break
			}
		}

		if found == false {
			context.SetStatusCode(fasthttp.StatusBadRequest)
			context.SetBodyString(ErrCORSOriginNotFound.Error())
		} else {
			header.Set(fasthttp.HeaderAccessControlAllowMethods, methods)
			header.Set(fasthttp.HeaderAccessControlAllowHeaders, headers)

			if source != nil {
				source(context)
			}
		}
	}
}
