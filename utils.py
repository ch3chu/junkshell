import os
import random
import string

words = [
    "process", "thread", "memory", "user",
    "auto", "sys", "win", "app", "net",
    "data", "file", "random", "list", "get",
    "set", "add", "remove", "create",
    "delete", "update", "find", "search",
    "open", "close", "read", "write",
    "load", "unload", "link", "unlink",
    "reduce", "stack", "heap", "core", "task",
    "queue", "buffer", "cache", "pool",
    "lock", "sync", "async", "wait",
    "signal", "event", "timer", "clock",
    "port", "socket", "stream", "pipe",
    "fork", "spawn", "exec", "kill",
    "pause", "resume", "stop", "start",
    "init", "exit", "run", "halt",
    "copy", "move", "rename", "merge",
    "split", "sort", "filter", "map",
    "join", "trim", "parse", "erase",
    "encode", "decode", "hash", "crypt",
    "scan", "check", "test", "debug",
    "log", "trace", "dump", "clear",
    "reset", "flush", "sync", "commit",
    "rollback", "save", "restore", "backup",
    "fetch", "push", "pull", "send",
    "receive", "bind", "connect", "listen",
    "format", "convert", "compress", "extract",
    "index", "query", "insert", "drop",
    "grant", "revoke", "lock", "unlock",
    "build", "compile", "deploy", "release"
]

# Generate random string
def randomStr(_min, _max) -> str:
    res = [random.choices(words)[0] + "_"]
    length = random.randint(_min, _max)
    res.extend(random.choices(string.ascii_letters + string.digits + "_", k=length))
    return "".join(res)

# Generate random bytes
def randomBytes(length) -> bytes:
	return os.urandom(length)