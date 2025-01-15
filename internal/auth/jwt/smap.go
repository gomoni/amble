package jwt

import (
	"fmt"
	"time"
)

type Smap map[string]any

func (smap Smap) Get(key string) (any, error) {
	x, ok := smap[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return x, nil
}

func (smap Smap) GetString(key string) (string, error) {
	x, err := smap.Get(key)
	if err != nil {
		return "", err
	}
	r, ok := x.(string)
	if !ok {
		return "", fmt.Errorf("not a string: %s: %+v", key, x)
	}
	return r, nil
}

func (smap Smap) GetInt(key string) (int, error) {
	x, err := smap.Get(key)
	if err != nil {
		return 0, err
	}
	f, ok := x.(float64)
	if ok {
		return int(f), nil
	}
	i, ok := x.(int)
	if ok {
		return i, nil
	}
	return 0, fmt.Errorf("not a number: %s: %+v", key, x)
}

func (smap Smap) FromUnix(key string) (time.Time, error) {
	tm, err := smap.GetInt(key)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(tm), 0).UTC(), nil
}

func (smap Smap) Must(key string) any {
	s, err := smap.Get(key)
	if err != nil {
		panic(err)
	}
	return s
}

func (smap Smap) MustString(key string) string {
	s, err := smap.GetString(key)
	if err != nil {
		panic(err)
	}
	return s
}

func (smap Smap) MustInt(key string) int {
	i, err := smap.GetInt(key)
	if err != nil {
		panic(err)
	}
	return i
}
