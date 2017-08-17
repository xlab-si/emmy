package storage

import (
	"io/ioutil"
	"os"
)

func Store(content []byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	err = ioutil.WriteFile(path, content, 0644)
	f.Write(content)

	if err != nil {
		return err
	}

	return nil
}

func Load(path string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
