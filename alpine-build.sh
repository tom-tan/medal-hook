#!/bin/sh

apk --no-cache add dub ldc gcc musl-dev git

dub build -b release-static || exit 1
strip bin/medal-hook
