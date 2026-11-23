.PHONY: all test jpl cwe ladder bench clean docker-build docker-run

# Default target runs all verification suites
all: test

# Install Python dependencies
deps:
	pip install -r requirements.txt

# Run complete verification suite
test:
	python3 challenge_runner.py --all

# Run NASA JPL Power of 10 Safety Audit
jpl:
	python3 challenge_runner.py --jpl

# Run NIST SAMATE Juliet CWE Suite
cwe:
	python3 challenge_runner.py --cwe

# Run 10-Level Adversarial Attack Ladder
ladder:
	python3 challenge_runner.py --ladder

# Run High-Throughput Endurance Benchmark
bench:
	python3 challenge_runner.py --bench

# Build Docker image
docker-build:
	docker build -t lia-challenge .

# Run inside Docker container
docker-run:
	docker run --rm -it lia-challenge

# Clean up Python bytecode and temporary caches
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf adversarial_reports/
