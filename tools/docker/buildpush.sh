#!/bin/bash

set -e
docker build -t rubinlinux/nefarious2:`git describe --long --always` -t rubinlinux/nefarious2:latest
docker push rubinlinux/nefarious2:`git describe  --long --always`
