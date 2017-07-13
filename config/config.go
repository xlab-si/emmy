package config

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

// init loads the default config file
func init() {
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
	LoadConfig("defaults", "yml")
}

// LoadConfig reads in the config file with configName being the name of the file (without suffix)
// and configType being "yml" or "json".
func LoadConfig(configName string, configType string) {
	viper.SetConfigName(configName)
	viper.SetConfigType(configType)

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Cannot read configuration file: %s\n", err))
	}
}

// LoadServerPort returns the port where emmy server will be listening.
func LoadServerPort() int {
	return viper.GetInt("port")
}

// LoadServerEndpoint returns the endpoint of the emmy server where clients will be contacting it.
func LoadServerEndpoint() string {
	ip := viper.GetString("ip")
	port := LoadServerPort()
	return fmt.Sprintf("%v:%v", ip, port)
}

// LoadTimeout returns the specified number of seconds that clients wait before giving up
// on connection to emmy server
func LoadTimeout() float64 {
	return viper.GetFloat64("timeout")
}

func LoadKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadTestKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadDLog(scheme string) *dlog.ZpDLog {
	dlogMap := viper.GetStringMap(scheme)
	p, _ := new(big.Int).SetString(dlogMap["p"].(string), 10)
	g, _ := new(big.Int).SetString(dlogMap["g"].(string), 10)
	q, _ := new(big.Int).SetString(dlogMap["q"].(string), 10)
	dlog := dlog.ZpDLog{
		P:               p,
		G:               g,
		OrderOfSubgroup: q,
	}

	return &dlog
}

func LoadPseudonymsysUserSecret(user, dlogType string) *big.Int {
	m := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", user, dlogType))
	s, _ := new(big.Int).SetString(m["secret"].(string), 10)
	return s
}

func LoadPseudonymsysOrgSecrets(orgName, dlogType string) (*big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, dlogType))
	s1, _ := new(big.Int).SetString(org["s1"].(string), 10)
	s2, _ := new(big.Int).SetString(org["s2"].(string), 10)
	return s1, s2
}

func LoadPseudonymsysOrgPubKeys(orgName string) (*big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, "dlog"))
	h1, _ := new(big.Int).SetString(org["h1"].(string), 10)
	h2, _ := new(big.Int).SetString(org["h2"].(string), 10)
	return h1, h2
}

func LoadPseudonymsysOrgPubKeysEC(orgName string) (*big.Int, *big.Int, *big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, "ecdlog"))
	h1X, _ := new(big.Int).SetString(org["h1x"].(string), 10)
	h1Y, _ := new(big.Int).SetString(org["h1y"].(string), 10)
	h2X, _ := new(big.Int).SetString(org["h2x"].(string), 10)
	h2Y, _ := new(big.Int).SetString(org["h2y"].(string), 10)
	return h1X, h1Y, h2X, h2Y
}

func LoadPseudonymsysCASecret() *big.Int {
	ca := viper.GetStringMap("pseudonymsys.ca")
	s, _ := new(big.Int).SetString(ca["d"].(string), 10)
	return s
}

func LoadPseudonymsysCAPubKey() (*big.Int, *big.Int) {
	ca := viper.GetStringMap("pseudonymsys.ca")
	x, _ := new(big.Int).SetString(ca["x"].(string), 10)
	y, _ := new(big.Int).SetString(ca["y1"].(string), 10)
	return x, y
}
