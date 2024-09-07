.PHONY: FORCE
all: FORCE
	$(MAKE) -C .. bitcoin_qt test_zenium_qt
clean: FORCE
	$(MAKE) -C .. bitcoin_qt_clean test_zenium_qt_clean
check: FORCE
	$(MAKE) -C .. test_zenium_qt_check
bitcoin-qt bitcoin-qt.exe: FORCE
	 $(MAKE) -C .. bitcoin_qt
apk: FORCE
	$(MAKE) -C .. bitcoin_qt_apk
