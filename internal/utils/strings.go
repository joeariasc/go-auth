package utils

import (
	"encoding/json"
	"fmt"
)

// PrettyPrintData takes a single argument 'data' of any type (interface{}).
func PrettyPrintData(data interface{}) {
	// Convert data to pretty-printed JSON.
	if prettyOutput, err := json.MarshalIndent(data, "", "  "); err == nil {
		fmt.Println(string(prettyOutput))
	} else {
		fmt.Println("error:", err)
	}
}
