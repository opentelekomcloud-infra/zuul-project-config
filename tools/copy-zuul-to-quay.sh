#!/usr/bin/env bash

TAG=$1


for img in zuul-executor zuul-scheduler zuul-merger zuul-web nodepool-launcher nodepool-builder; do
  echo -n "Copying docker.io/zuul/${img}:$TAG to quay.io/opentelekomcloud/${img}:$TAG"
  skopeo copy docker://docker.io/zuul/${img}:${TAG} docker://quay.io/opentelekomcloud/${img}:${TAG} -a
done
