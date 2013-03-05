#!/bin/bash

TMPDIR=$2
mkdir $TMPDIR
cd $TMPDIR
/data/farm/bro-bin/bin/bro -r $1 policy/protocols/http/var-extraction-uri.bro
