package collector

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"time"
)

type WebcamGrabber struct{}

func NewWebcamGrabber() *WebcamGrabber {
	return &WebcamGrabber{}
}

func (w *WebcamGrabber) Capture() (*WebcamCapture, error) {
	width := 640
	height := 480

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(128 + x%128),
				G: uint8(128 + y%128),
				B: 128,
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return &WebcamCapture{
		Data:      buf.Bytes(),
		Width:     width,
		Height:    height,
		Format:    "png",
		Timestamp: time.Now(),
	}, nil
}
