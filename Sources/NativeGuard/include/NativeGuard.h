#ifndef NATIVE_GUARD_H
#define NATIVE_GUARD_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
typedef struct { int32_t pid, ppid; uint32_t uid, status; uint64_t started; char path[4096]; char name[64]; } CSGProcess;
typedef struct { int32_t fd, kind, family, state, socket_type, protocol_number; uint16_t local_port, remote_port; char local[64], remote[64], tun[32]; } CSGSocket;
/* 0 = readable live identity, 1 = kernel-confirmed zombie, 2 = kernel-confirmed absent, negative = unknown/error. */
enum { CSG_PROCESS_ZOMBIE = 1, CSG_PROCESS_GONE = 2 };
int csg_process(int32_t pid, CSGProcess *out);
int csg_pids(int32_t *pids, int capacity);
int csg_sockets(int32_t pid, CSGSocket *out, int capacity);
int csg_listen(const char *path, uint32_t owner);
int csg_connect(const char *path);
int csg_peer(int fd, unsigned char token[32], uint32_t *uid, int32_t *pid);
typedef struct { int32_t pid, input, output, error; } CSGCommand;
/* Spawn a new process group with only stdin/out/err inherited. Parent ends are nonblocking. */
int csg_command_spawn(const char *path, char *const argv[], CSGCommand *out);
/* Fixed leaf tools inside guard-probe inherit its outer managed group. */
int csg_command_spawn_inherited(const char *path, char *const argv[], CSGCommand *out);
/* Observe without reaping, retaining the group leader identity during cleanup. */
int csg_command_exited(int32_t pid, int32_t *status);
/* 0 = no executable group members except leader, 1 = live members, -1 = unknown. */
int csg_command_group_active(int32_t leader);
int csg_probe(int family, int tcp, uint32_t index, const char *source, const char *target, uint16_t source_port, uint16_t target_port, int timeout_ms, int stun, int *sent);
typedef struct { int32_t stage, error; uint64_t elapsed_ms; } CSGProbeDiagnostics;
enum { CSG_PROBE_SOCKET=1, CSG_PROBE_BOUND_IF=2, CSG_PROBE_ADDRESS=3, CSG_PROBE_BIND=4,
       CSG_PROBE_NONBLOCKING=5, CSG_PROBE_CONNECT=6, CSG_PROBE_POLL=7,
       CSG_PROBE_SOCKET_ERROR=8, CSG_PROBE_SEND=9, CSG_PROBE_RECEIVE=10 };
int csg_probe_detailed(int family, int tcp, uint32_t index, const char *source, const char *target, uint16_t source_port, uint16_t target_port, int timeout_ms, int stun, int *sent, CSGProbeDiagnostics *diagnostics);
int csg_route_open(void);
int csg_route_read(int fd);
int csg_route_read_event(int fd, uint32_t *interface_index);
int csg_route_message(const void *data, size_t length, uint32_t *interface_index);
#endif
