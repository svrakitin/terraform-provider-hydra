package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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
func retryThrottledHydraAction(fn func() (*http.Response, error), backOff backoff.BackOff) error {
	if backOff == nil || reflect.ValueOf(backOff).IsNil() {
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

// checkResourceAttrJSON compares the JSON structure by unmarshalling both the actual and expected values into Go maps and comparing those, rather than comparing the raw JSON strings.
func checkResourceAttrJSON(resourceName, attributeName, expectedJSON string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		actualValue := rs.Primary.Attributes[attributeName]
		var actualMap, expectedMap map[string]interface{}

		if err := json.Unmarshal([]byte(actualValue), &actualMap); err != nil {
			return fmt.Errorf("failed to unmarshal actual JSON: %s", err)
		}
		if err := json.Unmarshal([]byte(expectedJSON), &expectedMap); err != nil {
			return fmt.Errorf("failed to unmarshal expected JSON: %s", err)
		}

		if !equalJSONMaps(actualMap, expectedMap) {
			return fmt.Errorf("JSON mismatch for attribute %s: expected %v, got %v", attributeName, expectedMap, actualMap)
		}

		return nil
	}
}

func equalJSONMaps(a, b map[string]interface{}) bool {
	return reflect.DeepEqual(a, b)
}
