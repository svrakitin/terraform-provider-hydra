package provider

import (
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ptr[T any](v T) *T {
	return &v
}

func strSlice(items []interface{}) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = item.(string)
	}
	return result
}

// diffSuppressMatchingDurationStrings compares two string time durations and returns true if they are equal, regardless of formatting.
func diffSuppressMatchingDurationStrings(k, old, new string, d *schema.ResourceData) bool {
	oldDuration, err := time.ParseDuration(old)
	if err != nil {
		return false
	}

	newDuration, err := time.ParseDuration(new)
	if err != nil {
		return false
	}

	return oldDuration == newDuration
}
