package logging

import (
	"fmt"
	"path"
	"runtime"
	"strings"
)

// GetLogFrame ...
func GetLogFrame(skipFrames int) (string, string) {
	// We need the frame at index skipFrames+2, since we never want runtime.Callers and getFrame
	targetFrameIndex := skipFrames + 2

	// Set size to targetFrameIndex+2 to ensure we have room for one more caller than we need
	programCounters := make([]uintptr, targetFrameIndex+2)
	n := runtime.Callers(0, programCounters)

	frame := runtime.Frame{Function: "unknown"}
	if n > 0 {
		frames := runtime.CallersFrames(programCounters[:n])
		for more, frameIndex := true, 0; more && frameIndex <= targetFrameIndex; frameIndex++ {
			var frameCandidate runtime.Frame
			frameCandidate, more = frames.Next()
			if frameIndex == targetFrameIndex {
				frame = frameCandidate
			}
		}
	}
	fun := strings.Split(frame.Function, ".")
	return fmt.Sprintf("%s", fun[len(fun)-1]), fmt.Sprintf("%s:%d", path.Base(frame.File), frame.Line)
}
