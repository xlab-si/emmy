#
# Copyright 2017 XLAB d.o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM golang:latest

LABEL maintainer="XLAB d.o.o" \
      description="This image starts the core emmy server"

# Create appropriate directory structure
RUN mkdir -p $GOPATH/src/github.com/xlab-si/emmy

# Run subsequent commands from the project root
WORKDIR $GOPATH/src/github.com/xlab-si/emmy

# Copy project from host to project directory in container
COPY ./ ./

# Install dependencies and compile the project
RUN make setup_dep && \
    dep ensure && \
    go install

# Start emmy server
ENTRYPOINT ["emmy", "server", "start"]

# Set default arguments for entrypoint command
CMD ["--loglevel", "debug", "--db", "redis:6379"]

EXPOSE 7007
