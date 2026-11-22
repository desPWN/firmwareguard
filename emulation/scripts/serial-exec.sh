#!/bin/bash
# serial-exec.sh — Execute a command via QEMU serial console and capture output
#
# Usage: serial-exec.sh <command> [timeout_seconds]
#
# Connects to the QEMU serial console Unix socket, sends the command wrapped
# in unique markers, captures output between markers, and prints the result.
# Exit code reflects the guest command's exit code (or 124 for timeout).
#
# This solves the problem that `echo cmd | socat` closes immediately on EOF
# before any output can be read. Instead we keep the connection open with a
# background sleep, monitor for an end marker, then extract the output.

set -u

CMD="$1"
TIMEOUT="${2:-30}"
SOCK="/tmp/qemu-serial.sock"

if [ ! -S "$SOCK" ]; then
    echo "Serial socket not found: $SOCK" >&2
    exit 1
fi

# Unique marker for this execution (alphanumeric only for shell safety)
MK="FGE${$}$(date +%s)"
START_MK="FIRMWAREGUARD_START_${MK}"
END_MK="FIRMWAREGUARD_END_${MK}_"

RAW="/tmp/_sout_$$"
rm -f "$RAW"
trap 'rm -f "$RAW"' EXIT

# For very long commands (>512 chars), base64-encode to avoid serial line buffer
# truncation. Most normal commands stay direct so minimal BusyBox guests without
# a base64 applet work reliably.
if [ ${#CMD} -gt 512 ]; then
    B64=$(printf '%s' "$CMD" | base64 -w 0)
    INNER_CMD="echo ${B64}|base64 -d|sh"
else
    INNER_CMD="$CMD"
fi

# Split markers with empty quotes in the transmitted command so the serial TTY's
# command-line echo (containing literal `""`) never matches the real output lines.
# Avoid subshell parentheses `(...)` for compatibility with BusyBox msh; the
# serial console already merges stdout and stderr onto the same stream.
START_SEND="FIRMWAREGUARD_START_\"\"${MK}"
END_SEND="FIRMWAREGUARD_END_\"\"${MK}_"
WRAPPED="echo ${START_SEND}; ${INNER_CMD}; echo ${END_SEND}\$?"

# Background: pipe the command into socat and capture all serial output.
# The sleep keeps the connection alive so output can be received.
# Send Ctrl-C first to interrupt any stuck foreground process, then a newline
# to activate any pending console prompt before running the command.
{
    sleep 0.3          # wait for socat connection to establish
    printf '\x03'      # Ctrl-C to kill any stuck foreground process
    sleep 0.3
    printf '\n'        # get a fresh prompt
    sleep 0.3
    printf '%s\n' "$WRAPPED"
    sleep "$TIMEOUT"   # keep connection alive until timeout
} | timeout "$((TIMEOUT + 3))" socat -T"$((TIMEOUT + 2))" - "UNIX-CONNECT:$SOCK" > "$RAW" 2>/dev/null &
SOCAT_PID=$!

# Monitor for the real end marker + numeric exit code (never matches echoed command)
DEADLINE=$((SECONDS + TIMEOUT + 1))
FOUND=0
while [ $SECONDS -lt $DEADLINE ]; do
    if [ -f "$RAW" ] && grep -qE "${END_MK}[0-9]+" "$RAW" 2>/dev/null; then
        FOUND=1
        sleep 0.2  # let final bytes flush
        kill $SOCAT_PID 2>/dev/null || true
        break
    fi
    sleep 0.2
done

wait $SOCAT_PID 2>/dev/null || true

if [ "$FOUND" -eq 0 ]; then
    # Timed out — print whatever we got and exit 124
    echo "FIRMWAREGUARD_SERIAL_TIMEOUT"
    cat "$RAW" 2>/dev/null || true
    exit 124
fi

# Extract output strictly between the real START and END marker lines.
OUTPUT=$(awk "/${START_MK}/{found=1; next} /${END_MK}[0-9]+/{exit} found{print}" "$RAW")

# Strip ANSI escape sequences, OSC sequences, and carriage returns from output
OUTPUT=$(printf '%s' "$OUTPUT" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\x1b\][^\x07]*\x07//g; s/\r//g')

# Extract exit code from the end marker line: FIRMWAREGUARD_END_<marker>_<exitcode>
EXIT_CODE=$(grep -oE "${END_MK}[0-9]+" "$RAW" 2>/dev/null | tail -1 | sed "s/${END_MK}//")
EXIT_CODE="${EXIT_CODE:-1}"

# Print captured output
printf '%s\n' "$OUTPUT"
exit "$EXIT_CODE"
