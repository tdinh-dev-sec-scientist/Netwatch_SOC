"""
Small-sample statistics for detection scorecards. Standard library only.

A detection benchmark usually has a handful of attack scenarios, so a bare
"6/6" says less than it looks like it does. Every rate in a scorecard carries
an interval, and comparisons between two engines carry an exact p-value.
"""

import math

Z95 = 1.959963984540054


def wilson(k, n, z=Z95):
    """Wilson score interval for a binomial proportion k/n.

    Well behaved at k == 0 and k == n, where the normal approximation
    collapses to a zero-width interval. Returns (low, high), or None if n == 0.
    """
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _log_comb(n, k):
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher_exact(k1, n1, k2, n2):
    """Two-sided Fisher exact test on two proportions, k1/n1 vs k2/n2.

    Sums the probability of every table with the same margins that is no more
    likely than the observed one (the convention R and SciPy use).
    """
    if not (0 <= k1 <= n1 and 0 <= k2 <= n2):
        raise ValueError('counts must satisfy 0 <= k <= n')
    total, successes = n1 + n2, k1 + k2
    lo, hi = max(0, successes - n2), min(successes, n1)
    log_denom = _log_comb(total, n1)

    def prob(x):
        return math.exp(_log_comb(successes, x)
                        + _log_comb(total - successes, n1 - x) - log_denom)

    observed = prob(k1)
    p = sum(prob(x) for x in range(lo, hi + 1)
            if prob(x) <= observed * (1 + 1e-7))
    return min(1.0, p)


def binomial_two_sided(k, n, p0):
    """Exact two-sided binomial test of k successes in n trials against p0."""
    if n == 0:
        return 1.0

    def prob(x):
        if p0 in (0.0, 1.0):
            return 1.0 if x == round(p0 * n) else 0.0
        return math.exp(_log_comb(n, x) + x * math.log(p0)
                        + (n - x) * math.log(1 - p0))

    observed = prob(k)
    return min(1.0, sum(prob(x) for x in range(n + 1)
                        if prob(x) <= observed * (1 + 1e-7)))


# ── Poisson rates ────────────────────────────────────────────────────────────

def _gamma_p(a, x):
    """Regularized lower incomplete gamma P(a, x) (Numerical Recipes 6.2)."""
    if x <= 0:
        return 0.0
    if x < a + 1:
        term = total = 1.0 / a
        ap = a
        for _ in range(10000):
            ap += 1
            term *= x / ap
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        return total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    # Continued fraction for Q(a, x), modified Lentz.
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
    return 1.0 - math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def _poisson_cdf(k, mu):
    """P(X <= k) for X ~ Poisson(mu)."""
    if k < 0:
        return 0.0
    return 1.0 - _gamma_p(k + 1, mu)


def _bisect(f, lo, hi, target):
    """Solve f(x) == target for a monotone f on [lo, hi]."""
    increasing = f(hi) > f(lo)
    for _ in range(200):
        mid = (lo + hi) / 2
        if (f(mid) < target) == increasing:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def poisson_rate_ci(count, exposure, alpha=0.05):
    """Exact (Garwood) interval for a rate: `count` events over `exposure`.

    Used for false alerts per host-hour. Returns (low, high) in events per
    unit of exposure, or None when there is no exposure.
    """
    if exposure <= 0:
        return None
    upper_mu = _bisect(lambda mu: _poisson_cdf(count, mu),
                       0.0, count * 10 + 50, alpha / 2)
    lower_mu = 0.0 if count == 0 else _bisect(
        lambda mu: _poisson_cdf(count - 1, mu), 0.0, count * 10 + 50,
        1 - alpha / 2)
    return lower_mu / exposure, upper_mu / exposure


def poisson_rate_test(k1, t1, k2, t2):
    """Exact conditional test that two Poisson rates k1/t1 and k2/t2 are equal.

    Given k1 + k2 events, k1 is binomial with p = t1 / (t1 + t2) under the null.
    """
    if t1 <= 0 or t2 <= 0:
        return None
    return binomial_two_sided(k1, k1 + k2, t1 / (t1 + t2))
