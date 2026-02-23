package model

// GenerateRequest represents a password generation request.
// Pointer bools allow distinguishing between missing (nil -> default true) and explicit false.
type GenerateRequest struct {
	Length    int   `json:"length"`
	Uppercase *bool `json:"uppercase"`
	Lowercase *bool `json:"lowercase"`
	Numbers   *bool `json:"numbers"`
	Symbols   *bool `json:"symbols"`
}

// GenerateResponse represents a password generation response.
type GenerateResponse struct {
	Password string `json:"password"`
	Length   int    `json:"length"`
}
