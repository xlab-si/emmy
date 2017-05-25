package config

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

func init() {
	//viper.AddConfigPath("C:/Users/Manca/goworkspace/src/github.com/xlab-si/emmy/config")
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
	LoadConfig("server")
	//LoadConfig("client")
}

func LoadConfig(configName string) {
	viper.SetConfigName(configName)
	viper.SetConfigType("yml")

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Cannot read configuration file: %s\n", err))
	}
}

func LoadKeyDirFromConfig() string {
	return viper.GetString("key_folder")
}

func LoadServerPort() int {
	return viper.GetInt("port")
}

func LoadServerEndpoint() string {
	ip := viper.GetString("ip")
	port := LoadServerPort()
	return fmt.Sprintf("%v:%v", ip, port)
}

func LoadTestKeyDirFromConfig() string {
	LoadConfig("test")
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadPseudonymsysDLog() *dlog.ZpDLog {
	dlogMap := viper.GetStringMap("pseudonymsys")
	p, _ := new(big.Int).SetString(dlogMap["P"].(string), 10)
	g, _ := new(big.Int).SetString(dlogMap["G"].(string), 10)
	q, _ := new(big.Int).SetString(dlogMap["Q"].(string), 10)
	dlog := dlog.ZpDLog{
		P:               p,
		G:               g,
		OrderOfSubgroup: q,
	}

	return &dlog
}
