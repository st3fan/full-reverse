#!/usr/bin/env python3
"""Run local lookup benchmarks and save revision, environment, metrics, and output."""

import argparse
from collections import Counter
import datetime
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def capture(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def parse_samples(chunks):
    # go test -json can split a benchmark's name and metrics across Output
    # events. Reassemble physical lines before parsing the report.
    samples = []
    for line in "".join(chunks).splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].startswith("Benchmark") and fields[1].isdigit():
            metrics = {}
            for index in range(2, len(fields) - 1, 2):
                metrics[fields[index + 1]] = float(fields[index])
            samples.append({"name": fields[0], "iterations": int(fields[1]), "metrics": metrics})
    return samples


def successful(report, count):
    samples = report["samples"]
    counts = Counter(s["name"] for s in samples)
    return (report["exit_code"] == 0 and not report["failed_events"] and bool(samples) and
            all(n == count for n in counts.values()) and
            all(s["metrics"].get("complete") == 1 for s in samples) and
            not any("--- FAIL:" in line for line in report["output"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", default="^BenchmarkLookup$", help="Go benchmark expression")
    parser.add_argument("--count", type=int, default=3, help="repeated samples (default: 3)")
    parser.add_argument("--output", type=Path, required=True, help="JSON report destination")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    destination = args.output.resolve()
    if destination.exists():
        parser.error("--output already exists; use a new filename to preserve results")

    command = ["go", "test", "-run", "^$", "-bench", args.bench, "-benchtime=1x",
               "-count", str(args.count), "-benchmem", "-timeout", "10m", "-json", "."]
    environment = json.loads(capture("go", "env", "-json", "GOOS", "GOARCH", "GOVERSION",
                                     "GOTOOLCHAIN", "GOAMD64", "CGO_ENABLED"))
    cpu_model = platform.processor()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu_model = line.partition(":")[2].strip()
                break
    report = {
        "schema_version": 1,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "revision": capture("git", "rev-parse", "HEAD"),
        "source_dirty": bool(capture("git", "status", "--porcelain")),
        "environment": {**environment, "platform": platform.platform(), "cpu_model": cpu_model,
                        "logical_cpus": os.cpu_count(), "GOMAXPROCS": os.getenv("GOMAXPROCS", "default")},
        "command": shlex.join(command),
        "samples": [],
        "output": [],
        "failed_events": [],
    }
    # Fixture setup, result validation, and counters live in the Go harness. A
    # mismatch fails go test; this wrapper never turns a failed run into a baseline.
    print(report["command"], flush=True)
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            report["output"].append(line)
            print(line, end="", flush=True)
            continue
        output = event.get("Output", "")
        if event.get("Action") == "fail":
            report["failed_events"].append(event)
        if output:
            report["output"].append(output)
            print(output, end="", flush=True)
    report["exit_code"] = process.wait()
    report["samples"] = parse_samples(report["output"])
    # Go exits successfully even if a benchmark expression matches nothing.
    report["success"] = successful(report, args.count)
    report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    print(f"Report: {destination}", flush=True)
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
