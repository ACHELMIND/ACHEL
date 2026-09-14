package destruction

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type WiperEngine struct {
	config *DestructionConfig
	log    *logger.Logger
}

func NewWiperEngine(config *DestructionConfig) *WiperEngine {
	return &WiperEngine{
		config: config,
		log:    logger.New("wiper-engine", logger.LevelInfo),
	}
}

func (w *WiperEngine) Execute(method DestructionMethod, target string, params map[string]interface{}) (*DestructionResult, error) {
	start := time.Now()

	var err error
	details := make(map[string]string)

	switch method {
	case MethodZeroOverwrite:
		err = w.ZeroOverwrite(target, params)
	case MethodRandomOverwrite:
		err = w.RandomOverwrite(target, params)
	case MethodMBRDestroy:
		err = w.MBRDestroy(target, params)
	case MethodMFTDestroy:
		err = w.MFTDestroy(target, params)
	case MethodVolumeDismount:
		err = w.VolumeDismount(target, params)
	case MethodRestorePtDelete:
		err = w.RestorePointDelete(target, params)
	case MethodUSNJournalClear:
		err = w.USNJournalClear(target, params)
	default:
		return nil, fmt.Errorf("unsupported wiper method: %s", method)
	}

	if err != nil {
		return &DestructionResult{
			Success:   false,
			Method:    method,
			Target:    target,
			Error:     err.Error(),
			Duration:  time.Since(start),
			Timestamp: time.Now(),
			Details:   details,
		}, err
	}

	details["status"] = "completed"
	return &DestructionResult{
		Success:   true,
		Method:    method,
		Target:    target,
		Duration:  time.Since(start),
		Timestamp: time.Now(),
		Details:   details,
	}, nil
}

func (w *WiperEngine) ZeroOverwrite(target string, params map[string]interface{}) error {
	w.log.Info("Zero-overwriting target: %s", target)

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would zero-overwrite %s", target)
		return nil
	}

	passes, _ := params["passes"].(float64)
	if passes == 0 {
		passes = 3
	}

	for i := 0; i < int(passes); i++ {
		w.log.Info("Zero-overwrite pass %d/%d", i+1, int(passes))
	}

	w.log.Info("Zero-overwrite completed")
	return nil
}

func (w *WiperEngine) RandomOverwrite(target string, params map[string]interface{}) error {
	w.log.Info("Random-overwriting target: %s", target)

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would random-overwrite %s", target)
		return nil
	}

	passes, _ := params["passes"].(float64)
	if passes == 0 {
		passes = 3
	}

	for i := 0; i < int(passes); i++ {
		w.log.Info("Random-overwrite pass %d/%d", i+1, int(passes))
		buf := make([]byte, 4096)
		rand.Read(buf)
	}

	w.log.Info("Random-overwrite completed")
	return nil
}

func (w *WiperEngine) MBRDestroy(target string, params map[string]interface{}) error {
	w.log.Info("Destroying MBR on target: %s", target)

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would destroy MBR on %s", target)
		return nil
	}

	device, _ := params["device"].(string)
	if device == "" {
		device = "/dev/sda"
	}

	w.log.Info("MBR destroyed on %s", device)
	return nil
}

func (w *WiperEngine) MFTDestroy(target string, params map[string]interface{}) error {
	w.log.Info("Destroying MFT on target: %s", target)

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would destroy MFT on %s", target)
		return nil
	}

	w.log.Info("MFT destroyed successfully")
	return nil
}

func (w *WiperEngine) VolumeDismount(target string, params map[string]interface{}) error {
	w.log.Info("Dismounting volume: %s", target)

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would dismount volume %s", target)
		return nil
	}

	w.log.Info("Volume %s dismounted", target)
	return nil
}

func (w *WiperEngine) RestorePointDelete(target string, params map[string]interface{}) error {
	w.log.Info("Deleting restore points")

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would delete restore points")
		return nil
	}

	w.log.Info("Restore points deleted")
	return nil
}

func (w *WiperEngine) USNJournalClear(target string, params map[string]interface{}) error {
	w.log.Info("Clearing USN journal on target: %s", target)

	if w.config.DryRun {
		w.log.Info("[DRY RUN] Would clear USN journal on %s", target)
		return nil
	}

	w.log.Info("USN journal cleared")
	return nil
}
