# Shell

A root shell on the TV, on a page in the Vetro dashboard, laid out like a terminal: the prompt sits under the output
and each command stays in the scrollback with what it printed. One command at a time; `cd` is remembered between
commands, history is kept, and each command has a time limit you choose (10, 30 or 60 s).

Keys: Enter runs · ↑ ↓ history · Ctrl+C drops the line you are typing · Ctrl+U clears it · Ctrl+L or `clear`
clears the screen. Ctrl+C does not stop a command that is already running: the time limit does.

It is the dashboard counterpart of Vetro's `POST /exec`, with bounded input and a working directory. Only paired
devices can open it, like the rest of Vetro.

## Permissions

`exec`: running the commands you type is the whole point of this Shard.

## Commands it runs

| Command | Why |
| --- | --- |
| **the command you type**, exactly as typed | that is what a shell does; nothing runs unless you press Enter |
| a wrapper around it: `cd '<cwd>'`, then your command, then `printf` of the directory it ended in | to carry the working directory over to the next command |

How a command is run, so you can check it in `index.js` (`build()`):

- It travels base64-encoded and runs in a fresh `bash` (or `sh` when the TV has no bash), with stdin on
  `/dev/null`, so a command that waits for input ends instead of holding Vetro's command queue.
- The directory comes back after a marker line carrying a random per-request nonce, so a command's own output
  cannot fake it.
- Limits: command 16 KB, output 256 KB (marked as cut), time limit 1–60 s (default 30 s). One command at a time.
  Every Vetro TV command goes through one queue, so remapper actions and everything else wait while a command
  runs: that is why the limit stops at 60 s.
- Programs that need a terminal or keyboard input (`vi`, `top`, `less`) do not work: use `top -b -n 1`, `cat`, …
  Variables and aliases are not kept between commands.

The Shard runs nothing by itself: no timer, no command at start.

**A command typed here runs as root and can damage the TV's system.** Read it before you run it.

## Network

None. The page talks only to its own routes on the TV (`run`, `state`, `settings`, `history/clear`).

## Data it keeps

Its own `config.json` on the TV:

- **History:** the last 200 commands you ran, shown with ↑ ↓, in plain text. Commands can contain secrets typed on
  the command line, so the page has **Clear history**, and **Save history** can be switched off. Off deletes what
  was saved and nothing more is written; the page still remembers this session's commands until you close it.
  Removing the Shard deletes the file.
- The last working directory, so the prompt comes back where you left it.

## Tested

Samsung QE43Q60BAUXXN (Q60B, 2022, firmware T-NKLBDEUC-1720.7), Tizen 6.5 (kernel 5.4, ARMv7), Vetro 0.5.0,
installed from a file: commands run as uid 0 in
bash 3.2.57, `cd /opt/... && ls` carried the directory over, stderr and exit codes shown, `cat` returned at once with
stdin closed. Also tested off the TV inside Vetro 0.5.0's plugin host, and on a local shell for odd directory names
(quotes, `$()`), exit codes and a spoofed marker.
