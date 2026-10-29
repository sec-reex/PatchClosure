Work in this directory. Your task is in task.md — read it now and follow it.

Also available: work/pcg_guide.md — static analysis notes on the code change
(file:line facts: what the change modifies, which related entry points
exist, decode steps near the checks, and a suggested review order). Treat it
like any tool's output: use what helps, and verify its claims against the
source as you go.

Two more files in work/ may help: endpoints.md lists which paths the
running service answered during setup (read-only checks — the observable you
need may surface on a different endpoint than the one you send input to;
re-check the others after each input), and notes.md is your own log.
