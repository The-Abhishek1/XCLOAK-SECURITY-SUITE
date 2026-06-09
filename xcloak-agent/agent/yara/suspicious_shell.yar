rule SuspiciousShell
{
    strings:
        $cmd1 = "bash -i"
        $cmd2 = "/dev/tcp"

    condition:
        any of them
}