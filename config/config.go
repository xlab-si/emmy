package config

import (
	"fmt"
	"github.com/spf13/viper"
)

func init() {
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
}

func LoadConfig(configName string) {
	viper.SetConfigName(configName)
	viper.SetConfigType("yml")

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Cannot read configuration file: %s\n", err))
	}
}

func LoadKeyDirFromConfig() (string) {
	LoadConfig("cli")
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadTestKeyDirFromConfig() (string) {
	LoadConfig("test")
	key_path := viper.GetString("key_folder")
	return key_path
}