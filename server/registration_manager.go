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

package server

import (
	"github.com/go-redis/redis"
)

// RegistrationManager checks for the presence of a registration key,
// removing it in case it exists.
// The bolean return argument indicates success (registration key
// present and subsequently deleted) or failure (absence of registration
// key).
type RegistrationManager interface {
	CheckRegistrationKey(string) (bool, error)
}

type RedisClient struct {
	*redis.Client
}

func NewRedisClient(c *redis.Client) *RedisClient {
	return &RedisClient{
		Client: c,
	}
}

// CheckRegistrationKey checks whether provided key is present in registration database and deletes it,
// preventing another registration with the same key.
// Returns true if key was present (registration allowed), false otherwise.
func (c *RedisClient) CheckRegistrationKey(key string) (bool, error) {
	resp := c.Del(key)

	err := resp.Err()

	if err != nil {
		return false, err
	}

	return resp.Val() == 1, nil // one deleted entry indicates that the key was present in the DB
}
