import psutil
import yara
import os
import concurrent.futures
import logging
from datetime import datetime
import time

DIRNAME = "/lib/x86_64-linux-gnu/liblzma.so.5.6.1"


start_time = time.time()

rule_path = "xzbotrule.txt"
rules = yara.compile(filepath=rule_path)
results = []
match = rules.match(DIRNAME)

if match:
    for match in match:
        result = f"file {DIRNAME} matches rule '{match.rule} with string:\n"
        for s in match.strings:
            result += f"   - {s}\n"
        results.append(result)

current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"results_{current_time}.txt" if results else f"no_results_{current_time}.txt"

with open(filename, "w") as f:
    if results:
        for result in results:
            f.write(result)
            f.write("\n")
    else:
        f.write("No results\n")

    end_time = time.time()
    total_time = end_time - start_time
    f.write(f"\nTotal scan time: {total_time:.2f} seconds\n")