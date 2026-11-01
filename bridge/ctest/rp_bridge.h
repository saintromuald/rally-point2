/*
 * rp_bridge.h — C interface to the rally-point-bridge static library.
 *
 * The embedding game calls every function from its game thread, polled and
 * never blocking (except rp_start, which dials the relay within a bounded
 * timeout — call it during a loading screen).
 *
 * All multi-byte integers in poll events are little-endian.
 */
#ifndef RP_BRIDGE_H
#define RP_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rp_session rp_session;

/* Error codes (negative), and rp_status values. */
#define RP_OK 0
#define RP_ERR_PANIC -100
#define RP_ERR_SETUP -200
#define RP_ERR_DIAL -201
#define RP_ERR_START_TIMEOUT -202
#define RP_ERR_TURN_ENDED -1
#define RP_ERR_TURN_FULL -2
#define RP_STAT_STARTING 0
#define RP_STAT_RUNNING 1
#define RP_STAT_ENDED 2

/* Poll event kinds (the first byte of each event). */
#define RP_EV_TURN 1   /* u8, u32 slot, u64 seq, u32 len, len bytes */
#define RP_EV_BUFFER 2 /* u8, u32 buffer_turns */
#define RP_EV_LEAVE 3  /* u8, u32 slot, u32 reason */
#define RP_EV_LOBBY 4  /* u8, u32 slot, u32 len, len bytes */

/* Starts a session from the launch JSON; writes *out. Returns 0 on success. */
int32_t rp_start(const char *setup_json, rp_session **out);

/* Driver health: RP_STAT_*, or a negated DriverError code. */
int32_t rp_status(rp_session *session);

/* The seeded latency-buffer depth, in turns. */
uint32_t rp_initial_buffer(rp_session *session);

/* This client's slot in the session. */
uint32_t rp_local_slot(rp_session *session);

/* OUT: queue the game's assembled turn. 0 queued; -2 full (retry); -1 ended. */
int32_t rp_submit_turn(rp_session *session, uint32_t frame,
                       const uint8_t *data, size_t len);

/* IN: drain turns/directives/leaves into buf; returns bytes written (walk it
 * event by event), or a negative error. */
int32_t rp_poll(rp_session *session, uint32_t frame, uint8_t *buf, size_t cap);

/* Fire-and-forget signals. */
void rp_result_expected(rp_session *session);
void rp_send_result(rp_session *session, const uint8_t *data, size_t len);
void rp_leave_intent(rp_session *session);
void rp_game_started(rp_session *session);

/* Teardown (idempotent). */
void rp_end(rp_session *session);

uint32_t rp_bridge_version(void);

#ifdef __cplusplus
}
#endif

#endif /* RP_BRIDGE_H */
