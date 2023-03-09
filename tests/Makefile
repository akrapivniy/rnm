SUBDIRS = tools common read perf-event

ifndef SOURCES_DIR
SOURCES_DIR := $(shell ( pwd -L ) )
endif

all clean install:
	$(foreach dir, $(SUBDIRS), $(MAKE) -C $(SOURCES_DIR)/$(dir) \
	SOURCES_DIR=$(SOURCES_DIR)/$(dir) $@ ; )