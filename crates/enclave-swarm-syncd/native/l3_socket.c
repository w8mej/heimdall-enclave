/* Own-process socket observation through the SDK ABI, never copied offsets.
 * SO_ACCEPTCONN is not a supported getsockopt query on Darwin. */
#include <errno.h>
#include <libproc.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int depot_l3_tcp_listener(int fd, int *listening, int *observed,
                           int *expected) {
  struct socket_fdinfo info;
  memset(&info, 0, sizeof(info));
  *expected = (int)sizeof(info);
  *observed =
      proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
  if (*observed != *expected)
    return -1;
  if ((info.psi.soi_family != AF_INET && info.psi.soi_family != AF_INET6) ||
      info.psi.soi_type != SOCK_STREAM || info.psi.soi_kind != SOCKINFO_TCP ||
      info.psi.soi_protocol != IPPROTO_TCP) {
    errno = EPROTOTYPE;
    return -1;
  }
  *listening = info.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN ||
               (info.psi.soi_options & SO_ACCEPTCONN) != 0;
  return 0;
}
