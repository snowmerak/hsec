package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func init() {
	application.RegisterEvent[fidoEvent]("vault:fido-waiting")
	application.RegisterEvent[fidoEvent]("vault:fido-resolved")
	application.RegisterEvent[dekRotationProgress]("vault:dek-rotation-progress")
}

func main() {
	dataDir, err := defaultVaultDataDir()
	if err != nil {
		log.Fatal(err)
	}
	vaultService, err := NewVaultService(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := vaultService.close(); err != nil {
			log.Printf("close vault: %v", err)
		}
	}()

	app := application.New(application.Options{
		Name:        "hsec",
		Description: "A small FIDO2-backed personal vault",
		Services: []application.Service{
			application.NewService(vaultService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})
	vaultService.setEmitter(func(name string, data any) {
		app.Event.Emit(name, data)
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "hsec",
		Width:     1000,
		Height:    618,
		MinWidth:  760,
		MinHeight: 520,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(6, 7, 15),
		URL:              "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
