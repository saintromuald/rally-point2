/*
 * ctest.c — Phase 1's C smoke test: start a session from a launch JSON file,
 * pump synthetic turns, and report what the relay fans back.
 *
 *   ctest <setup.json> <turns>
 *
 * Sends <turns> lockstep turns (a 0x05 keep-alive plus a fake 0x0C build
 * command), polling after each submit. Exits 0 when it has received <turns>
 * turns from peers; nonzero on a session error. Run two instances (slot 0 and
 * slot 1) against the same relay.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rp_bridge.h"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        exit(2);
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void read_u32(const uint8_t **p, const uint8_t *end, uint32_t *out) {
    if (*p + 4 > end) {
        fprintf(stderr, "ctest: truncated event\n");
        exit(3);
    }
    memcpy(out, *p, 4);
    *p += 4;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <setup.json> <turns>\n", argv[0]);
        return 2;
    }
    long turns = strtol(argv[2], NULL, 10);
    char *json = read_file(argv[1]);

    rp_session *session = NULL;
    int rc = rp_start(json, &session);
    if (rc != RP_OK) {
        fprintf(stderr, "ctest: rp_start failed: %d\n", rc);
        return 1;
    }
    printf("ctest: session started, local slot %u, initial buffer %u turns\n",
           rp_local_slot(session), rp_initial_buffer(session));
    fflush(stdout);
    rp_game_started(session);

    /* A turn mixing the pre-game lobby commands and Hyperion-wide commands the
     * relay must validate: 0x05 keep-alive (1), 0x3C StartGame (1), 0x3D
     * download progress (2), 0x3E modify slot (6), 0x3F version (8), 0x40
     * version verify (18), 0x41 change race (3), 0x42 change team (2), 0x44
     * change slot (3), 0x45 swap slots (3), 0x48 seed init (13), 0x54 end
     * briefing (1), 0x5B make public (1), then 0x38 pause (1), 0x39 resume (1),
     * 0x0C build (8), 0x89 wide select of 2 units (2 + 4*2), 0x8C selection
     * chunk of 2 units (3 + 4*2), 0x94 wide right-click (12). */
    static const uint8_t turn[105] = {
        0x05,
        0x3C,
        0x3D, 0,
        0x3E, 0, 0, 0, 0, 0,
        0x3F, 0, 0, 0, 0, 0, 0, 0,
        0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x41, 0, 0,
        0x42, 0,
        0x44, 0, 0,
        0x45, 0, 0,
        0x48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x54,
        0x5B,
        0x38,
        0x39,
        0x0C, 1, 2, 3, 4, 5, 6, 7,
        0x89, 2, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x8C, 2, 0x09, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x94, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0,
    };
    uint8_t events[4096];
    uint32_t received = 0;

    for (long i = 0; i < turns; i++) {
        for (;;) {
            rc = rp_submit_turn(session, (uint32_t)(i + 1), turn, sizeof(turn));
            if (rc == RP_ERR_TURN_FULL) {
                /* Storm backpressure: the step stalls, retry the turn. */
                continue;
            }
            break;
        }
        if (rc != RP_OK) {
            fprintf(stderr, "ctest: rp_submit_turn: %d\n", rc);
            break;
        }

        /* Lockstep pacing: hold this step until the peer's turn arrives
         * (the game would stall waiting for the step exactly the same way). */
        for (int spin = 0; received <= (uint32_t)i && spin < 5000; spin++) {
            int32_t nbytes =
                rp_poll(session, (uint32_t)(i + 1), events, sizeof(events));
            if (nbytes < 0) {
                fprintf(stderr, "ctest: rp_poll: %d\n", nbytes);
                break;
            }
            const uint8_t *p = events;
            const uint8_t *end = events + nbytes;
            while (p < end) {
                uint8_t kind = *p++;
                if (kind == RP_EV_TURN) {
                    uint32_t slot, len;
                    uint64_t seq;
                    read_u32(&p, end, &slot);
                    memcpy(&seq, p, 8);
                    p += 8;
                    read_u32(&p, end, &len);
                    p += len;
                    printf("ctest: turn from slot %u (seq %llu, %u bytes)\n",
                           slot, (unsigned long long)seq, len);
                    received++;
                } else if (kind == RP_EV_BUFFER) {
                    uint32_t depth;
                    read_u32(&p, end, &depth);
                    printf("ctest: buffer directive -> %u turns\n", depth);
                } else if (kind == RP_EV_LEAVE) {
                    uint32_t slot, reason;
                    read_u32(&p, end, &slot);
                    read_u32(&p, end, &reason);
                    printf("ctest: slot %u left (reason 0x%x)\n", slot, reason);
                } else if (kind == RP_EV_LOBBY) {
                    uint32_t slot, len;
                    read_u32(&p, end, &slot);
                    read_u32(&p, end, &len);
                    p += len;
                    printf("ctest: lobby command from slot %u (%u bytes)\n",
                           slot, len);
                } else {
                    fprintf(stderr, "ctest: unknown event kind %u\n", kind);
                    exit(3);
                }
            }

            int32_t st = rp_status(session);
            if (st != RP_STAT_RUNNING) {
                printf("ctest: session ended with status %d\n", st);
                goto done;
            }
            struct timespec ts = {0, 1000000}; /* 1 ms */
            nanosleep(&ts, NULL);
        }
        if (received <= (uint32_t)i) {
            fprintf(stderr, "ctest: stalled at step %ld\n", i + 1);
            break;
        }
    }

done:
    rp_leave_intent(session);
    printf("ctest: received %u of %ld turns\n", received, turns);
    rp_end(session);
    free(json);
    return received >= (uint32_t)turns ? 0 : 1;
}
