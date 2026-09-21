.PHONY: validate check

validate:
	omarchy plugin validate .

check: validate
	python3 -m compileall -q bin core
