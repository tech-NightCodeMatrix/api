package domain


type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ID       string `json:"id"`
}
