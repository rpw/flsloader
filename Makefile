.PHONY = install

UNAME := $(shell uname -s)

IDAPATH := /Applications/idaq.app

ifeq ($(UNAME),Darwin)
IDAPATH := /Applications/idaq.app
	IDALOADERPATH := ${IDAPATH}/Contents/MacOS/loaders
endif
ifeq ($(UNAME),Linux)
IDAPATH := /opt/ida/
	IDALOADERPATH := ${IDAPATH}/loaders
endif
ifeq ($(UNAME),Win32)
IDAPATH := 'C:\Program Files\IDA'
	IDALOADERPATH := ${IDAPATH}/loaders
endif

install:
	cp flsloader.py ${IDALOADERPATH}/flsloader.py
