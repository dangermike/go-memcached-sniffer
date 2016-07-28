#! /usr/bin/env bash

set +e

if [ ! -f "$(which ragel)" ]; then (
  echo "Failed to find ragel executable"
  exit 1
)
fi

for filename in $(ls *.rl); do
  outfile=${filename%.*}.go
  echo "compiling ${filename} ${outfile}"
  ragel -Z -G2 $filename | gofmt > ${outfile}
done
