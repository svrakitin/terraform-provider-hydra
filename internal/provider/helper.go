package provider

func strPtr(str string) *string {
	return &str
}

func strSlice(items []interface{}) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = item.(string)
	}
	return result
}
