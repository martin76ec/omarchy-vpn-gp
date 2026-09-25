.PHONY: validate test check

validate:
	omarchy plugin validate .

test:
	python3 -m unittest discover -s tests -t .

check: validate test
	python3 -m compileall -q bin core
