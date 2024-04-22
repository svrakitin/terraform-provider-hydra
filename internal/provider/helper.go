package provider

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
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

// retryThrottledHydraAction executes the fn function and if backOff is set, retries the function if the request is throttled.
func retryThrottledHydraAction(fn func() (*http.Response, error), backOff *backoff.ExponentialBackOff) error {
	if backOff == nil {
		_, err := fn()
		return err
	}

	retryAction := func() error {
		resp, err := fn()

		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
				fmt.Println("Throttled, retrying...")
				return err
			}

			return backoff.Permanent(err)
		}

		return nil
	}

	return backoff.Retry(retryAction, backOff)
}

func validateDuration(val interface{}, key string) (ws []string, errors []error) {
	v, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be string", key))
		return
	}

	if _, err := time.ParseDuration(v); err != nil {
		errors = append(errors, fmt.Errorf("%q must be a valid duration string: %s", key, err))
	}
	return
}
