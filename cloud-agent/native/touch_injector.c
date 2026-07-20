// ============================================================
// 法器: DeltaForge/cloud-agent/native/touch_injector.c
// 描述: /dev/uinput 底层触摸注入 — 伪装 "fts_ts" I2C 触摸屏
//       绕开 InputDispatcher 检测层（adb input 在 InputReader 层可见）
// 编译: aarch64-linux-android21-clang -static -Os -o touch_injector touch_injector.c
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/uinput.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <sys/time.h>

static int ufd = -1;
static int sw = 1080, sh = 2400;

static int uinit(void) {
    ufd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (ufd < 0) ufd = open("/dev/input/uinput", O_WRONLY | O_NONBLOCK);
    if (ufd < 0) { perror("uinput open"); return -1; }

    ioctl(ufd, UI_SET_EVBIT, EV_KEY);
    ioctl(ufd, UI_SET_EVBIT, EV_SYN);
    ioctl(ufd, UI_SET_EVBIT, EV_ABS);
    ioctl(ufd, UI_SET_KEYBIT, BTN_TOUCH);
    ioctl(ufd, UI_SET_KEYBIT, BTN_TOOL_FINGER);
    ioctl(ufd, UI_SET_ABSBIT, ABS_MT_SLOT);
    ioctl(ufd, UI_SET_ABSBIT, ABS_MT_TOUCH_MAJOR);
    ioctl(ufd, UI_SET_ABSBIT, ABS_MT_POSITION_X);
    ioctl(ufd, UI_SET_ABSBIT, ABS_MT_POSITION_Y);
    ioctl(ufd, UI_SET_ABSBIT, ABS_MT_PRESSURE);
    ioctl(ufd, UI_SET_ABSBIT, ABS_MT_TRACKING_ID);

    struct uinput_abs_setup ax = {.code = ABS_MT_POSITION_X, .absinfo = {0, sw-1, 0, 0, 11}};
    ioctl(ufd, UI_ABS_SETUP, &ax);

    struct uinput_abs_setup ay = {.code = ABS_MT_POSITION_Y, .absinfo = {0, sh-1, 0, 0, 11}};
    ioctl(ufd, UI_ABS_SETUP, &ay);

    struct uinput_setup us;
    memset(&us, 0, sizeof(us));
    snprintf(us.name, UINPUT_MAX_NAME_SIZE, "fts_ts");
    us.id.bustype = BUS_I2C; us.id.vendor = 0x0001;
    us.id.product = 0x0002;  us.id.version = 1;
    ioctl(ufd, UI_DEV_SETUP, &us);
    ioctl(ufd, UI_DEV_CREATE);
    usleep(100000);
    return 0;
}

static void ev_send(int type, int code, int value) {
    struct input_event e = {0};
    gettimeofday(&e.time, NULL);
    e.type = type; e.code = code; e.value = value;
    write(ufd, &e, sizeof(e));
}

static void syn(void) { ev_send(EV_SYN, SYN_REPORT, 0); }

static void mt_slot(int s)   { ev_send(EV_ABS, ABS_MT_SLOT, s); }
static void mt_x(int v)      { ev_send(EV_ABS, ABS_MT_POSITION_X, v); }
static void mt_y(int v)      { ev_send(EV_ABS, ABS_MT_POSITION_Y, v); }
static void mt_p(int v)      { ev_send(EV_ABS, ABS_MT_PRESSURE, v); }
static void mt_major(int v)  { ev_send(EV_ABS, ABS_MT_TOUCH_MAJOR, v); }

static void down(int x, int y, int p) {
    mt_slot(0); mt_major(8 + p/32); mt_x(x); mt_y(y); mt_p(p);
    ev_send(EV_KEY, BTN_TOUCH, 1);
    ev_send(EV_KEY, BTN_TOOL_FINGER, 1);
    mt_slot(0);
    ev_send(EV_ABS, ABS_MT_TRACKING_ID, 0);
    syn();
}

static void up(void) {
    mt_slot(0);
    ev_send(EV_ABS, ABS_MT_TRACKING_ID, -1);
    ev_send(EV_KEY, BTN_TOUCH, 0);
    syn();
}

static void move(int x, int y, int p) {
    mt_slot(0); mt_x(x); mt_y(y); mt_p(p); syn();
}

static int rand_range(int lo, int hi) {
    return lo + (rand() % (hi - lo + 1));
}

static void do_tap(int x, int y, int p, int dur) {
    if (ufd < 0 && uinit() < 0) return;
    down(x, y, p);
    if (dur > 0) usleep(dur * 1000);
    up();
}

static void do_swipe(int x1, int y1, int x2, int y2, int dur, int steps, int curve) {
    if (ufd < 0 && uinit() < 0) return;
    if (steps < 1) steps = 10;
    int us = (dur * 1000) / steps;
    down(x1, y1, 200);
    usleep(us / 2);
    for (int i = 1; i <= steps; i++) {
        float t = (float)i / (float)steps;
        float ct = curve ? t * t * (3.0f - 2.0f * t) : t;
        int cx = (int)(x1 + (x2 - x1) * ct);
        int cy = (int)(y1 + (y2 - y1) * ct);
        if (curve && i > 2 && i < steps - 1) cy += rand_range(-7, 7);
        int pr = 200 + (int)(55.0f * (1.0f - fabsf(2.0f * t - 1.0f)));
        move(cx, cy, pr);
        usleep(us);
    }
    up();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s tap <x> <y> [pressure] [dur_ms]\n", argv[0]);
        fprintf(stderr, "      %s swipe <x1> <y1> <x2> <y2> [dur_ms] [steps] [curve]\n", argv[0]);
        return 1;
    }
    srand(time(NULL));
    if (uinit() < 0) return 1;

    if (!strcmp(argv[1], "tap") && argc >= 4) {
        int x = atoi(argv[2]), y = atoi(argv[3]);
        int p = argc >= 5 ? atoi(argv[4]) : 220;
        int d = argc >= 6 ? atoi(argv[5]) : 50;
        do_tap(x, y, p, d);
        printf("tap %d,%d p=%d dur=%dms\n", x, y, p, d);
    } else if (!strcmp(argv[1], "swipe") && argc >= 6) {
        int x1 = atoi(argv[2]), y1 = atoi(argv[3]);
        int x2 = atoi(argv[4]), y2 = atoi(argv[5]);
        int d = argc >= 7 ? atoi(argv[6]) : 300;
        int s = argc >= 8 ? atoi(argv[7]) : 15;
        int c = argc >= 9 ? atoi(argv[8]) : 1;
        do_swipe(x1, y1, x2, y2, d, s, c);
        printf("swipe %d,%d -> %d,%d dur=%dms steps=%d curve=%d\n", x1, y1, x2, y2, d, s, c);
    }
    ioctl(ufd, UI_DEV_DESTROY);
    close(ufd);
    return 0;
}
