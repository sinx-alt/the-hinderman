import sys

from detectors.inspect import inspect

if len(sys.argv) < 2:
    raise SystemExit('Usage: python -m detectors "text to inspect"')
for finding in inspect(" ".join(sys.argv[1:])):
    print(f"{finding.category}\t{finding.type}\t{finding.start}:{finding.end}\t{finding.confidence:.2f}")
