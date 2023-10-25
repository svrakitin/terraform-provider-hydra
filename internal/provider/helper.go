package provider

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
