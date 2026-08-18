package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// version is the app version shown in the UI. It defaults to "dev" and is overridden at
// build time via -ldflags "-X main.version=<tag>" (see the release workflow).
var version = "dev"

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:            "Kosh",
		Width:            1280,
		Height:           800,
		MinWidth:         900,
		MinHeight:        600,
		DisableResize:    false,
		Frameless:        true, // custom in-app title bar provides min/max/close
		BackgroundColour: &options.RGBA{R: 10, G: 10, B: 15, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:     app.startup,
		OnDomReady:    app.domReady,
		OnBeforeClose: app.beforeClose,
		Bind:          []interface{}{app},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			IsZoomControlEnabled:              false,
			DisablePinchZoom:                  true,
			DisableFramelessWindowDecorations: false,
			Theme:                             windows.SystemDefault,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
