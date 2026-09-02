"""BoundedStageQueue: capacity, backpressure, drop accounting, shutdown."""

import threading
import time

import pytest

from netwatch.pipeline.queues import BoundedStageQueue, Closed, OverflowPolicy


def test_capacity_must_be_positive():
    with pytest.raises(ValueError):
        BoundedStageQueue('q', 0)


def test_put_and_get_round_trip():
    q = BoundedStageQueue('q', 4)
    assert q.put(['a', 'b'], 2) is True
    assert q.get() == ['a', 'b']
    snap = q.snapshot()
    assert snap['enqueued'] == 2
    assert snap['dequeued'] == 2
    assert snap['chunks_enqueued'] == 1


def test_counters_are_in_packets_and_capacity_is_in_chunks():
    q = BoundedStageQueue('q', 2)
    q.put(list(range(100)), 100)
    q.put(list(range(50)), 50)
    assert q.depth() == 2                      # two chunks
    assert q.snapshot()['enqueued'] == 150     # one hundred and fifty packets
    assert q.utilization() == 1.0


def test_get_returns_none_on_timeout_rather_than_blocking_forever():
    q = BoundedStageQueue('q', 2)
    started = time.perf_counter()
    assert q.get(timeout=0.05) is None
    assert time.perf_counter() - started < 1.0


def test_drop_policy_counts_the_whole_chunk():
    q = BoundedStageQueue('q', 1, policy=OverflowPolicy.DROP,
                          put_timeout_s=0.05)
    assert q.put([1, 2, 3], 3) is True
    assert q.put([4, 5, 6, 7], 4) is False
    snap = q.snapshot()
    assert snap['dropped'] == 4
    assert snap['enqueued'] == 3
    assert snap['block_events'] == 1


def test_block_policy_waits_for_space_instead_of_dropping():
    q = BoundedStageQueue('q', 1, policy=OverflowPolicy.BLOCK,
                          put_timeout_s=0.05)
    q.put(['first'], 1)
    accepted = []

    def producer():
        accepted.append(q.put(['second'], 1))

    thread = threading.Thread(target=producer)
    thread.start()
    time.sleep(0.15)
    assert not accepted, 'producer should still be blocked'
    assert q.get() == ['first']
    thread.join(timeout=5)
    assert accepted == [True]
    assert q.snapshot()['dropped'] == 0
    assert q.snapshot()['blocked_s'] > 0


def test_blocked_producer_is_released_by_close():
    """A shutdown must be able to interrupt backpressure, not deadlock on it."""
    q = BoundedStageQueue('q', 1, policy=OverflowPolicy.BLOCK,
                          put_timeout_s=0.05)
    q.put(['first'], 1)
    result = []

    thread = threading.Thread(target=lambda: result.append(q.put(['x'], 1)))
    thread.start()
    time.sleep(0.1)
    q.close()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result == [False]
    assert q.snapshot()['dropped'] == 1


def test_high_water_mark_records_the_deepest_the_queue_ever_got():
    q = BoundedStageQueue('q', 8)
    for i in range(5):
        q.put([i], 1)
    for _ in range(5):
        q.get()
    assert q.depth() == 0
    assert q.snapshot()['high_water'] == 5
    assert q.snapshot()['high_water_utilization'] == pytest.approx(5 / 8)


def test_close_signals_every_consumer_exactly_once():
    q = BoundedStageQueue('q', 8)
    q.close(consumers=3)
    for _ in range(3):
        with pytest.raises(Closed):
            q.get(timeout=0.5)


def test_items_queued_before_close_are_still_delivered():
    q = BoundedStageQueue('q', 8)
    q.put(['a'], 1)
    q.put(['b'], 1)
    q.close(consumers=1)
    assert q.get() == ['a']
    assert q.get() == ['b']
    with pytest.raises(Closed):
        q.get(timeout=0.5)


def test_snapshot_exposes_everything_the_metrics_endpoint_needs():
    q = BoundedStageQueue('capture->parse', 4, policy=OverflowPolicy.DROP)
    q.put([1], 1)
    snap = q.snapshot()
    assert set(snap) >= {'name', 'capacity', 'policy', 'depth', 'utilization',
                         'high_water', 'high_water_utilization', 'enqueued',
                         'dequeued', 'dropped', 'block_events', 'blocked_s'}
    assert snap['name'] == 'capture->parse'
    assert snap['policy'] == OverflowPolicy.DROP
