"""The live loop's own bookkeeping, tested without waiting on wall-clock minutes."""

import threading
import time


def test_live_windows_count_the_alerts_they_raised(simulator, monkeypatch):
    """Each live window must report the findings raised inside it.

    The loop used to initialise `window_alerts` and never increment it, so every
    engine row in performance_metrics claimed zero alerts no matter what fired.
    """
    windows = []
    monkeypatch.setattr(simulator, 'METRICS_WINDOW_S', 0.2)
    monkeypatch.setattr(simulator, 'FIRST_SCENARIO_DELAY_S', 3600)
    # Two findings for every frame: the accounting, not detection, is under test.
    monkeypatch.setattr(simulator, 'process', lambda frame, ts: ['f', 'f'])
    monkeypatch.setattr(simulator, 'maybe_flush', lambda: 0.0)
    monkeypatch.setattr(
        simulator, '_record_window',
        lambda elapsed, packets, alerts: windows.append((packets, alerts)))

    simulator.run(rate_pps=500, duration_s=1.0)

    assert windows, 'no metrics window closed during the run'
    for packets, alerts in windows:
        assert packets > 0
        assert alerts == 2 * packets


def test_stop_ends_the_live_loop(simulator, monkeypatch):
    monkeypatch.setattr(simulator, 'FIRST_SCENARIO_DELAY_S', 3600)
    worker = threading.Thread(target=simulator.run, kwargs={'rate_pps': 200},
                              daemon=True)
    worker.start()
    # run() sets _running itself; stopping before it does would be undone.
    deadline = time.time() + 5
    while not simulator._running and time.time() < deadline:
        time.sleep(0.01)
    simulator.stop()
    worker.join(timeout=5)
    assert not worker.is_alive()
