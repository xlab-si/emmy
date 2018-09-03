/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cl

import (
	"fmt"
	"math/big"

	"github.com/go-redis/redis"
)

type DBManager struct {
	*redis.Client
}

func NewDBManager(address string) (*DBManager, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: address,
	})
	err := redisClient.Ping().Err()
	if err != nil {
		return nil, fmt.Errorf("unable to connect to redis database (%s)", err)
	}
	return &DBManager{redisClient}, nil
}

func (m *DBManager) SetReceiverRecord(nym *big.Int, r *ReceiverRecord) error {
	return m.Set(nym.String(), r, 0).Err()
}

func (m *DBManager) GetReceiverRecord(nym *big.Int) (*ReceiverRecord, error) {
	r, err := m.Get(nym.String()).Result()
	if err != nil {
		return nil, err
	}
	var rec ReceiverRecord
	rec.UnmarshalBinary([]byte(r))

	return &rec, nil
}
