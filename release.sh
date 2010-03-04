#!/bin/sh

hg tip --template '{rev}:{node|short} {date|shortdate}' > .release

