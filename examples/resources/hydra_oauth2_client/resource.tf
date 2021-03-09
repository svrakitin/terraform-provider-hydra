resource "hydra_oauth2_client" "example" {
	client_id = "example"
	client_name = "example"

	metadata = {
		"first_party" = true
	}
    
	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "none"
}