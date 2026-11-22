#!/usr/bin/env python3
"""Drives a program that asks questions on /dev/tty, expect-style. Runs INSIDE the VM of the
`interactive` installer-vm cell (tests/installer-vm/run-cell.sh), as root. Standard library only.

    tty-driver.py <steps.json> <transcript> -- <command> [args...]

The command runs on a fresh pseudo-terminal as the session leader, so /dev/tty is that terminal.
<steps.json> is a list of steps, answered in order:

    {"expect": "<regex>", "send": "<text>"}       or
    {"expect": "<regex>", "send_file": "<path>"}   (a secret: read from the file, never from argv)
    optional "timeout": seconds to wait for the prompt (default 300)

A step waits for its regex in the output that follows the previous step's prompt, then writes the
answer and a newline. The whole terminal output (CR removed) goes to <transcript>; hidden answers
are not echoed, so a secret never reaches it. Exit status: the command's own, or 97 (it ended
before every step was answered), 98 (a prompt never came), 99 (usage or overall timeout).
"""
import json
import os
import pty
import re
import select
import signal
import sys
import time

TOTAL_TIMEOUT_S = 3000


def die(code, msg):
    sys.stderr.write("tty-driver: %s\n" % msg)
    sys.exit(code)


def main():
    if len(sys.argv) < 5 or sys.argv[3] != "--":
        die(99, "usage: tty-driver.py <steps.json> <transcript> -- <command> [args...]")
    with open(sys.argv[1]) as f:
        steps = json.load(f)
    argv = sys.argv[4:]
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)
    started = time.time()
    seen = ""
    done = 0
    step_deadline = started + steps[0].get("timeout", 300) if steps else None
    with open(sys.argv[2], "w") as log:
        while True:
            now = time.time()
            if now - started > TOTAL_TIMEOUT_S:
                os.kill(pid, signal.SIGKILL)
                die(99, "overall timeout after %d s" % TOTAL_TIMEOUT_S)
            if step_deadline is not None and now > step_deadline:
                os.kill(pid, signal.SIGKILL)
                die(
                    98,
                    "step %d: the prompt %r never came; the output ended with %r"
                    % (done + 1, steps[done]["expect"], seen[-300:]),
                )
            ready, _, _ = select.select([fd], [], [], 1.0)
            if not ready:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""  # EIO: the child closed the terminal
            if not data:
                break
            text = data.decode("utf-8", "replace").replace("\r", "")
            log.write(text)
            log.flush()
            seen += text
            while done < len(steps):
                m = re.search(steps[done]["expect"], seen)
                if not m:
                    break
                step = steps[done]
                if "send_file" in step:
                    with open(step["send_file"]) as sf:
                        answer = sf.read().strip()
                else:
                    answer = step["send"]
                os.write(fd, (answer + "\n").encode())
                answer = ""
                seen = seen[m.end():]
                done += 1
                if done < len(steps):
                    step_deadline = time.time() + steps[done].get("timeout", 300)
                else:
                    step_deadline = None
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if done < len(steps):
        die(
            97,
            "the command ended (status %d) before step %d (%r) was answered"
            % (code, done + 1, steps[done]["expect"]),
        )
    sys.stderr.write("tty-driver: the command exited %d after %d answers\n" % (code, done))
    sys.exit(code if code >= 0 else 128 - code)


main()
