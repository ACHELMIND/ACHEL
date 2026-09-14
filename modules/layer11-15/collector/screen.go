package collector

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"time"
)

func CaptureScreen() (*ScreenCapture, error) {
	width := 1920
	height := 1080

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(x % 256),
				G: uint8(y % 256),
				B: uint8((x + y) % 256),
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return &ScreenCapture{
		Data:      buf.Bytes(),
		Width:     width,
		Height:    height,
		Format:    "png",
		Timestamp: time.Now(),
	}, nil
}

func RecordScreen(duration time.Duration) (*ScreenRecord, error) {
	frames := int(duration.Seconds() * 30)
	if frames < 1 {
		frames = 1
	}

	data := make([]byte, 0)
	for i := 0; i < frames; i++ {
		frameData := []byte{0x00, 0x00, 0x00, 0xFF}
		data = append(data, frameData...)
	}

	return &ScreenRecord{
		Data:      data,
		Duration:  duration,
		Format:    "h264",
		Timestamp: time.Now(),
	}, nil
}
