#!/usr/bin/env python3
"""Compile the production Darwin observer and probe only owned child processes.

Run on the authorized non-root Mac from this repository. No daemon census,
installed services, accounts, mounts or privileged operations are exercised.
An absent observation must be proven: Unknown deliberately fails that assertion.
"""

import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HARNESS = r"""
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
int depot_holder_capture(int,uint32_t*,uint64_t*,uint32_t*);
int depot_holder_observe(int,uint32_t,uint64_t,uint32_t,uint64_t,uint64_t);
int depot_holder_signal(int,uint32_t,uint64_t,uint32_t,int);
static int passed=0,failed=0;
static void check(const char *mode,const char *name,int actual,int expected) {
    int ok=actual==expected;passed+=ok;failed+=!ok;
    printf("{\"mode\":\"%s\",\"check\":\"%s\",\"actual\":%d,\"expected\":%d,\"pass\":%s}\n",mode,name,actual,expected,ok?"true":"false");fflush(stdout);
}
static int ready(int fd) {
    struct pollfd p={.fd=fd,.events=POLLIN};char b=0;
    return poll(&p,1,3000)==1 && read(fd,&b,1)==1 && b=='R';
}
int main(int argc,char **argv) {
    alarm(45);
    if(argc!=3)return 2;
    int held=open(argv[1],O_RDONLY),other=open(argv[2],O_RDONLY);
    struct stat target,wrong;
    if(held<0 || other<0 || fstat(held,&target) || fstat(other,&wrong))return 2;
    for(int mode=0;mode<2;mode++) {
        const char *name=mode?"mmap-only":"fd-only";
        int command[2],reply[2];if(pipe(command)||pipe(reply))return 2;
        pid_t pid=fork();if(pid<0)return 2;
        if(pid==0) {
            alarm(15);signal(SIGHUP,SIG_IGN);close(command[1]);close(reply[0]);close(held);close(other);
            int fd=open(argv[1],O_RDONLY);if(fd<0)_exit(3);
            void *mapping=MAP_FAILED;
            if(mode) {mapping=mmap(NULL,4096,PROT_READ,MAP_PRIVATE,fd,0);if(mapping==MAP_FAILED)_exit(4);close(fd);fd=-1;}
            if(write(reply[1],"R",1)!=1)_exit(5);
            char op;if(read(command[0],&op,1)!=1)_exit(6);
            if(mapping!=MAP_FAILED)munmap(mapping,4096);
            if(fd>=0)close(fd);
            if(write(reply[1],"R",1)!=1)_exit(7);
            while(read(command[0],&op,1)==1){}
            _exit(0);
        }
        close(command[0]);close(reply[1]);
        if(!ready(reply[0])) {kill(pid,SIGKILL);waitpid(pid,NULL,0);return 2;}
        uint32_t uid=0,version=0;uint64_t birth=0;
        int captured=depot_holder_capture(pid,&uid,&birth,&version);
        check(name,"capture",captured,0);
        if(captured==0) {
            check(name,"held",depot_holder_observe(pid,uid,birth,version,(uint64_t)target.st_dev,target.st_ino),1);
            check(name,"wrong-inode-absent",depot_holder_observe(pid,uid,birth,version,(uint64_t)wrong.st_dev,wrong.st_ino),0);
            check(name,"wrong-incarnation-unknown",depot_holder_observe(pid,uid,birth,version+1,(uint64_t)target.st_dev,target.st_ino),-1);
            check(name,"wrong-incarnation-signal-refused",depot_holder_signal(pid,uid,birth,version+1,SIGHUP),ESRCH);
        }
        if(write(command[1],"R",1)!=1 || !ready(reply[0])) {kill(pid,SIGKILL);waitpid(pid,NULL,0);return 2;}
        if(captured==0) {
            check(name,"released-absent",depot_holder_observe(pid,uid,birth,version,(uint64_t)target.st_dev,target.st_ino),0);
            check(name,"live-incarnation-sighup",depot_holder_signal(pid,uid,birth,version,SIGHUP),0);
            int result=depot_holder_signal(pid,uid,birth,version,SIGTERM);
            check(name,"owned-incarnation-terminate",result,0);
            if(result!=0)kill(pid,SIGKILL); /* Owned fixture cleanup only. */
        } else kill(pid,SIGKILL);
        int status=0;waitpid(pid,&status,0);
        check(name,"owned-child-exit",WIFSIGNALED(status)?WTERMSIG(status):-1,SIGTERM);
        close(command[1]);close(reply[0]);
    }
    close(held);close(other);
    printf("{\"summary\":true,\"passed\":%d,\"failed\":%d}\n",passed,failed);
    return failed?1:0;
}
"""


def main():
    if sys.platform != "darwin" or os.geteuid() == 0:
        print(json.dumps({"status": "BLOCKED",
              "reason": "NONROOT_MACOS_REQUIRED"}))
        return 2
    root = Path(__file__).resolve().parents[1]
    source = root / "crates/enclave-core/native/holders.c"
    target = root / "target"
    target.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(
        prefix="phase1-native-holders-", dir=target))
    os.chmod(scratch, 0o700)
    harness = scratch / "probe.c"
    harness.write_text(HARNESS)
    for name in ("target", "other"):
        (scratch / name).write_bytes(bytes(4096))
        (scratch / name).chmod(0o400)
    command = [
        "xcrun",
        "clang",
        "-Wall",
        "-Wextra",
        str(source),
        str(harness),
        "-lproc",
        "-o",
        str(scratch / "probe"),
    ]
    report = {
        "host": platform.uname()._asdict(),
        "uid": os.getuid(),
        "artifact_directory": str(scratch),
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "observer_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "compile_command": command,
        "scope": "Same-user private fixtures only; not installed cross-UID acceptance",
    }
    built = subprocess.run(
        command, cwd=root, capture_output=True, text=True, timeout=30
    )
    report.update(
        compile_exit_code=built.returncode,
        compile_stdout=built.stdout,
        compile_stderr=built.stderr,
    )
    if built.returncode:
        report["status"] = "COMPILE_FAILED"
        print(json.dumps(report, indent=2))
        return 2
    report["binary_sha256"] = hashlib.sha256(
        (scratch / "probe").read_bytes()
    ).hexdigest()
    start = time.monotonic()
    process = subprocess.Popen(
        [str(scratch / "probe"), str(scratch / "target"), str(scratch / "other")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=50)
        report.update(
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            status="PASS" if process.returncode == 0 else "FAIL",
        )
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        report.update(exit_code=124, stdout=stdout,
                      stderr=stderr, status="TIMEOUT")
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    report["elapsed_seconds"] = round(time.monotonic() - start, 3)
    (scratch / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
