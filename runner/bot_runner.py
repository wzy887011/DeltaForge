# -*- coding: utf-8 -*-
# ============================================================
# 法器: DeltaForge/runner/bot_runner.py (v3 — 全链路行为随机化)
# 改进: 坐标高斯抖动 + 指数延迟 + 路线轮换 + 随机休息 + 8% 概率跳轮
#       ± uinput 触摸注入 (TouchInjector)
# ============================================================

import subprocess, time, json, os, sys, random, math

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "forge_config.json")
ROUTES_FILE = os.path.join(CONFIG_DIR, "map_routes.json")
SCREEN_W, SCREEN_H = 1080, 2400

DEFAULT_CFG = {
    "game_package": "com.tencent.tmgp.dfm",
    "max_runs": 50,
    "rest_min": 15, "rest_max": 45,
    "match_timeout": 600, "raid_timeout": 1200,
    "retry_limit": 3,
}


class Randomizer:
    """高斯分布随机化器"""

    @staticmethod
    def gauss(mu, sigma):
        return max(mu - 3 * sigma, min(mu + 3 * sigma, random.gauss(mu, sigma)))

    @staticmethod
    def exponential(mean):
        return -mean * math.log(max(0.0001, random.random()))

    @staticmethod
    def jitter(xy, sigma=0.025):
        return tuple(Randomizer.gauss(v, v * sigma) for v in xy)

    @staticmethod
    def human_delay(base, sigma=0.3):
        return Randomizer.gauss(base, abs(base) * sigma)


class TouchInjector:
    """底层触摸注入 — /dev/uinput"""

    def __init__(self):
        self.bin = None
        base = os.path.dirname(os.path.abspath(__file__))
        for loc in [
            os.path.join(base, "..", "cloud-agent", "native", "touch_injector"),
            os.path.join(base, "touch_injector"),
        ]:
            if os.path.exists(loc):
                self.bin = loc
                break

    def _run(self, args):
        cmd = self.bin + " " + args if self.bin else "input " + args
        subprocess.run(f"adb shell {cmd}", shell=True,
                       capture_output=True, text=True)

    def tap(self, x, y, pressure=None, duration_ms=None):
        p = pressure or random.randint(180, 255)
        d = duration_ms or random.randint(30, 120)
        if self.bin:
            self._run(f"tap {int(x)} {int(y)} {p} {d}")
        else:
            self._run(f"touchscreen tap {int(x)} {int(y)}")
            time.sleep(d / 1000.0)

    def swipe(self, x1, y1, x2, y2, duration_ms=None, curve=True):
        d = duration_ms or random.randint(150, 400)
        steps = random.randint(8, 20)
        if self.bin:
            self._run(f"swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {d} {steps} {1 if curve else 0}")
        else:
            self._run(f"touchscreen swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {d}")


class BotRunner:
    def __init__(self, cfg=None):
        self.cfg = cfg or self._load_cfg()
        self.runs = 0
        self.profit = 0
        self._running = False
        self._touch = TouchInjector()
        self._rng = Randomizer()

    def _load_cfg(self):
        c = dict(DEFAULT_CFG)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                c.update(json.load(f))
        return c

    def _load_routes(self):
        if os.path.exists(ROUTES_FILE):
            with open(ROUTES_FILE) as f:
                return json.load(f)
        return {"routes": [{
            "name": "default",
            "waypoints": [
                {"x": 0.45, "y": 0.75, "act": "move"},
                {"x": 0.48, "y": 0.68, "act": "loot"},
                {"x": 0.52, "y": 0.60, "act": "loot"},
                {"x": 0.55, "y": 0.50, "act": "move"},
                {"x": 0.42, "y": 0.35, "act": "extract"},
            ]
        }], "default_route": "default"}

    def _adb(self, cmd):
        return subprocess.run(f"adb shell {cmd}", shell=True,
                              capture_output=True, text=True).stdout.strip()

    def _ensure_game(self):
        out = self._adb(f"pidof {self.cfg['game_package']}")
        if out:
            return True
        self._adb(
            f"setprop wrap.{self.cfg['game_package']} "
            f"'LD_PRELOAD=/data/local/tmp/libforgehook.so'"
        )
        self._adb(
            f"am start -n {self.cfg['game_package']}/com.epicgames.ue4.SplashActivity"
        )
        for _ in range(40):
            time.sleep(2)
            if self._adb(f"pidof {self.cfg['game_package']}"):
                return True
        return False

    def _back_to_lobby(self):
        for _ in range(random.randint(2, 5)):
            self._adb("input keyevent BACK")
            time.sleep(self._rng.gauss(0.5, 0.15))
        tx = self._rng.gauss(540, 80)
        ty = self._rng.gauss(1200, 100)
        self._touch.tap(tx, ty)
        time.sleep(self._rng.gauss(2.5, 0.6))

    def _start_match(self):
        self._touch.tap(
            self._rng.gauss(800, 40), self._rng.gauss(2200, 30),
            pressure=random.randint(200, 255)
        )
        time.sleep(self._rng.gauss(2.5, 0.5))
        self._touch.tap(
            self._rng.gauss(540, 60), self._rng.gauss(1400, 80),
            pressure=random.randint(180, 240)
        )
        time.sleep(self._rng.gauss(1.5, 0.3))
        self._touch.tap(
            self._rng.gauss(800, 30), self._rng.gauss(2200, 20)
        )
        time.sleep(self._rng.gauss(0.8, 0.2))

    def _wait_match(self):
        dl = time.time() + self.cfg["match_timeout"]
        while time.time() < dl:
            out = self._adb("dumpsys activity activities | grep mResumedActivity")
            if "GameActivity" in out:
                time.sleep(self._rng.gauss(8.0, 2.0))
                return "in_game"
            time.sleep(2)
        return "timeout"

    def _run_route(self, route):
        jx, jy = random.randint(130, 170), random.randint(2050, 2150)
        for wi, wp in enumerate(route["waypoints"]):
            if not self._running:
                return False
            px, py = self._rng.jitter((wp["x"], wp["y"]), sigma=0.025)
            sx, sy = int(px * SCREEN_W), int(py * SCREEN_H)
            self._touch.swipe(jx, jy, sx, sy,
                              duration_ms=random.randint(180, 450), curve=True)
            time.sleep(self._rng.gauss(0.5, 0.2))
            act = wp.get("act", "move")
            if act == "loot":
                for _ in range(random.randint(2, 5)):
                    self._touch.tap(
                        self._rng.gauss(540, 100), self._rng.gauss(1800, 120),
                        pressure=random.randint(160, 240),
                        duration_ms=random.randint(30, 100)
                    )
                    time.sleep(self._rng.gauss(0.4, 0.12))
                if random.random() < 0.15:
                    time.sleep(-math.log(max(0.0001, random.random())) * 3.0)
            elif act == "extract":
                self._touch.tap(
                    self._rng.gauss(540, 50), self._rng.gauss(1800, 60),
                    pressure=255, duration_ms=random.randint(300, 800)
                )
                time.sleep(random.uniform(4, 8))
            time.sleep(self._rng.gauss(0.15, 0.06))
            jx, jy = sx, sy
        self.profit += random.randint(8000, 65000)
        return True

    def _wait_raid_end(self):
        dl = time.time() + self.cfg["raid_timeout"]
        while time.time() < dl:
            if not self._adb(f"pidof {self.cfg['game_package']}"):
                return "crashed"
            out = self._adb("dumpsys activity activities | grep mResumedActivity")
            if "GameActivity" not in out:
                return "done"
            time.sleep(random.randint(3, 7))
        return "timeout"

    def _post_raid(self):
        time.sleep(self._rng.gauss(3.0, 0.8))
        for _ in range(random.randint(2, 4)):
            self._touch.tap(
                self._rng.gauss(540, 80), self._rng.gauss(2200, 50)
            )
            time.sleep(self._rng.gauss(1.5, 0.4))
        self._back_to_lobby()

    def run(self):
        self._running = True
        routes = self._load_routes()
        pool = list(routes["routes"])
        random.shuffle(pool)
        fails = 0
        ri = 0
        while self._running and self.runs < self.cfg["max_runs"]:
            self.runs += 1
            route = pool[ri % len(pool)]
            if random.random() < 0.4:
                ri = random.randint(0, len(pool) - 1)
            else:
                ri += 1
            print(f"--- Run {self.runs}/{self.cfg['max_runs']} [{route['name']}] ---")
            if not self._ensure_game():
                fails += 1
                if fails > self.cfg["retry_limit"]:
                    print("[-] 游戏启动失败次数过多")
                    break
                time.sleep(30)
                continue
            lobby_wait = self._rng.gauss(5.0, 3.0)
            time.sleep(max(1, lobby_wait))
            self._back_to_lobby()
            time.sleep(self._rng.gauss(2.0, 0.6))
            if random.random() < 0.08:
                print("  [skip] 模拟休息一轮")
                time.sleep(random.randint(30, 60))
                continue
            self._start_match()
            mr = self._wait_match()
            if mr != "in_game":
                print(f"  匹配结果: {mr}")
                self._back_to_lobby()
                continue
            self._run_route(route)
            rr = self._wait_raid_end()
            print(f"  撤离结果: {rr}")
            self._post_raid()
            rest = max(5, min(self._rng.exponential(self.cfg["rest_max"]), 120))
            print(f"  休息 {rest:.0f}s, 累计收益 ~{self.profit:,}")
            time.sleep(rest)
            fails = 0
        print(f"Done: {self.runs} runs, ~{self.profit:,}")
        self._running = False

    def stop(self):
        self._running = False


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--runs", type=int, default=50)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    bot = BotRunner()
    if a.dry_run:
        rt = bot._load_routes()
        for r in rt["routes"]:
            print(f"  {r['name']}: {len(r['waypoints'])}wp")
        print("  Randomizer: 高斯抖动 + 指数延迟 + 路线轮换")
    else:
        try:
            bot.run()
        except KeyboardInterrupt:
            bot.stop()
