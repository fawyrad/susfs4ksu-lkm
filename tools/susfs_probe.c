// SPDX-License-Identifier: GPL-2.0-only
// From matsuzaka-yuki/susfs-lkm-module, commit
// 170c672ebff5a35ea30a7bee3949cc67a96c9710.
// Independent read-only wire probe. Existing/unknown implementations are never stacked.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct text_reply { char text[16]; int err; };

int main(void)
{
    if (geteuid() != 0) return 12;
    const unsigned commands[] = {0x555e1, 0x555e3};
    for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
        struct text_reply reply = { .text = {0}, .err = 126 };
        errno = 0;
        long result = syscall(SYS_reboot, 0xdeadbeefU, 0xfafafafaU, commands[i], &reply);
        if (reply.err != 126 || reply.text[0] != '\0') {
            puts("Existing SUSFS control interface detected (not a compatibility guarantee).");
            return 0;
        }
        // Reboot(2) must reject this magic with -EINVAL (or -ENOSYS). Returning success means
        // something else consumed the call and left the reply untouched, and any other errno
        // (a seccomp/denial path) hides the truth too: both are "cannot tell", not "absent".
        if (result != -1 || (errno != EINVAL && errno != ENOSYS)) return 12;
    }
    puts("No responding SUSFS version/variant interface.");
    return 10;
}
