"""
Coarse IP-to-country enrichment.

This is a small static prefix table, NOT a geolocation database. It covers the
address space the simulator uses plus a handful of well-known public ranges so
the geography module has something real to group by. Anything unmatched is
reported as 'UNKNOWN' rather than guessed.

For production accuracy, replace `lookup()` with a MaxMind GeoLite2 or
IP2Location query — the rest of the system only depends on the returned shape.
"""

# (first octet range, second octet range or None, country, lat, lon)
_PREFIXES = [
    ((185, 185), (220, 220), 'NL', 52.37, 4.90),
    ((45, 45), (33, 33), 'US', 37.77, -122.42),
    ((104, 104), (16, 31), 'US', 37.77, -122.42),
    ((8, 8), (8, 8), 'US', 37.75, -97.82),
    ((198, 198), (51, 51), 'US', 38.89, -77.03),
    ((203, 203), (0, 0), 'AU', -33.87, 151.21),
    ((91, 91), (108, 108), 'RU', 55.75, 37.62),
    ((95, 95), (163, 163), 'RU', 55.75, 37.62),
    ((223, 223), (5, 5), 'CN', 39.91, 116.39),
    ((114, 114), (114, 114), 'CN', 39.91, 116.39),
    ((202, 202), (108, 108), 'CN', 31.23, 121.47),
    ((5, 5), (22, 22), 'IR', 35.69, 51.39),
    ((175, 175), (45, 45), 'KP', 39.02, 125.75),
    ((77, 77), (88, 88), 'DE', 52.52, 13.40),
    ((51, 51), (15, 15), 'GB', 51.51, -0.13),
    ((13, 13), (112, 112), 'JP', 35.69, 139.69),
    ((177, 177), (0, 255), 'BR', -23.55, -46.63),
    ((49, 49), (44, 44), 'IN', 19.08, 72.88),
    ((41, 41), (0, 255), 'ZA', -26.20, 28.04),
    ((142, 142), (0, 255), 'CA', 43.65, -79.38),
]

UNKNOWN = ('UNKNOWN', None, None)
PRIVATE = ('PRIVATE', None, None)


def lookup(ip):
    """Return (country, latitude, longitude). Never raises."""
    if not ip or ':' in ip:
        return UNKNOWN
    try:
        a, b, _c, _d = (int(p) for p in ip.split('.'))
    except (ValueError, TypeError):
        return UNKNOWN
    if a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) \
            or (a == 192 and b == 168) or (a == 169 and b == 254):
        return PRIVATE
    for (a_lo, a_hi), b_range, country, lat, lon in _PREFIXES:
        if a_lo <= a <= a_hi:
            if b_range is None or b_range[0] <= b <= b_range[1]:
                return country, lat, lon
    return UNKNOWN


def is_high_risk(country):
    """Countries flagged for elevated scrutiny in the geography module.

    A crude proxy for threat-intel reputation; documented as such so nobody
    mistakes it for real intelligence.
    """
    return country in ('KP', 'IR', 'RU', 'CN')
