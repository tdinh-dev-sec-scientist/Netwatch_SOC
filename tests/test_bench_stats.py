"""NetWatch Bench statistics, checked against published reference values."""

import pytest

from netwatch_bench import stats


def test_wilson_matches_reference_values():
    low, high = stats.wilson(6, 6)
    assert low == pytest.approx(0.6097, abs=1e-4)
    assert high == 1.0
    low, high = stats.wilson(3, 6)
    assert (low, high) == pytest.approx((0.1876, 0.8124), abs=1e-4)
    assert stats.wilson(0, 10)[0] == 0.0
    assert stats.wilson(0, 0) is None


def test_fisher_exact_reproduces_the_six_case_comparison():
    # 6/6 vs 3/6: the README's headline comparison is not significant alone.
    assert stats.fisher_exact(6, 6, 3, 6) == pytest.approx(2 / 11, rel=1e-9)
    assert stats.fisher_exact(3, 6, 3, 6) == pytest.approx(1.0)
    assert stats.fisher_exact(10, 10, 0, 10) < 1e-4
    assert stats.fisher_exact(6, 6, 3, 6) == stats.fisher_exact(3, 6, 6, 6)
    with pytest.raises(ValueError):
        stats.fisher_exact(7, 6, 0, 6)


def test_poisson_rate_interval_is_the_exact_garwood_interval():
    low, high = stats.poisson_rate_ci(0, 10)
    assert low == 0.0
    assert high == pytest.approx(3.6889 / 10, rel=1e-4)
    low, high = stats.poisson_rate_ci(10, 1)
    assert (low, high) == pytest.approx((4.7954, 18.3904), rel=1e-4)
    assert stats.poisson_rate_ci(5, 0) is None


def test_poisson_rate_test():
    assert stats.poisson_rate_test(10, 10, 10, 10) == pytest.approx(1.0)
    assert stats.poisson_rate_test(82, 82, 2190, 82) < 1e-6
    assert stats.poisson_rate_test(1, 0, 1, 1) is None


def test_binomial_two_sided():
    # 9 of 10 heads against a fair coin: p = 22/1024.
    assert stats.binomial_two_sided(9, 10, 0.5) == pytest.approx(22 / 1024)
    assert stats.binomial_two_sided(0, 0, 0.5) == 1.0
