// wrapper for type(d) ids

package tid

import "go.jetify.com/typeid"

type userID struct{}

func (userID) Prefix() string { return "usr" }

type UserID struct {
	typeid.TypeID[userID]
}

func NewUserID() (UserID, error) {
	return typeid.New[UserID]()
}

func ParseUserID(s string) (UserID, error) {
	return typeid.Parse[UserID](s)
}
