package config

import (
	"fmt"
	"math/big"
	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/dlog"
)

func init() {
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
}

// Type can be "yml", "json" ...
func LoadConfig(configName string, ctype string) {
	viper.SetConfigName(configName)
	viper.SetConfigType(ctype)

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Cannot read configuration file: %s\n", err))
	}
}

func LoadKeyDirFromConfig() (string) {
	LoadConfig("cli", "yml")
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadTestKeyDirFromConfig() (string) {
	LoadConfig("test", "yml")
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadPseudonymsysDLogFromConfig() *dlog.ZpDLog {
	LoadConfig("dlogs", "json")
	dlogMap := viper.GetStringMap("pseudonymsys")
	p, _ := new(big.Int).SetString(dlogMap["P"].(string), 10)
	g, _ := new(big.Int).SetString(dlogMap["G"].(string), 10)
	q, _ := new(big.Int).SetString(dlogMap["Q"].(string), 10)
	dlog := dlog.ZpDLog{
		P: p,
		G: g,
		OrderOfSubgroup: q,
	}

	return &dlog	
}

func LoadPseudonymsysUserSecretFromConfig(user string) *big.Int {
	LoadConfig("secrets", "json")
	m := viper.GetStringMap("pseudonymsys")
	s, _ := new(big.Int).SetString(m[user].(string), 10)
	return s
}

func LoadPseudonymsysOrgSecretsFromConfig(org string) (*big.Int, *big.Int) {
	LoadConfig("secrets", "json")
	m := viper.GetStringMap("pseudonymsys")
	s1, _ := new(big.Int).SetString(m[org].(map[string]interface{})["s1"].(string), 10)
	s2, _ := new(big.Int).SetString(m[org].(map[string]interface{})["s2"].(string), 10)
	return s1, s2
}






