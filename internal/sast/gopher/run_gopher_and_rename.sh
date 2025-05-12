#!/bin/sh
cd /analysis/gopher || exit 1
./gopher ../repo
./rename_json.sh ../repo
