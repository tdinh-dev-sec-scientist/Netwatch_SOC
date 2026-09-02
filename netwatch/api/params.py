"""
Query-parameter parsing and validation.

Every endpoint takes its inputs through these helpers, so a bad value fails
the same way everywhere: a 400 with the parameter's name, what was received
and what was allowed. Nothing here ever reaches SQL as a string — sort keys
and enumerated values are resolved against allow-lists in the repository.
"""

from flask import request

from netwatch.api.errors import ValidationError

MAX_LIMIT = 500
MAX_OFFSET = 1_000_000

TRUE = {'1', 'true', 'yes', 'on'}
FALSE = {'0', 'false', 'no', 'off'}


def int_arg(name, default, low, high, args=None):
    args = request.args if args is None else args
    raw = args.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationError(
            "'%s' must be an integer" % name,
            {'parameter': name, 'received': raw}) from None
    if not low <= value <= high:
        raise ValidationError(
            "'%s' must be between %d and %d" % (name, low, high),
            {'parameter': name, 'received': value, 'min': low, 'max': high})
    return value


def float_arg(name, default, low, high, args=None):
    args = request.args if args is None else args
    raw = args.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValidationError(
            "'%s' must be a number" % name,
            {'parameter': name, 'received': raw}) from None
    if not low <= value <= high:
        raise ValidationError(
            "'%s' must be between %g and %g" % (name, low, high),
            {'parameter': name, 'received': value, 'min': low, 'max': high})
    return value


def choice_arg(name, allowed, default=None, args=None):
    args = request.args if args is None else args
    raw = args.get(name)
    if raw is None or raw == '':
        return default
    if raw not in allowed:
        raise ValidationError(
            "'%s' is not an allowed value for '%s'" % (raw, name),
            {'parameter': name, 'received': raw, 'allowed': sorted(allowed)})
    return raw


def bool_arg(name, default=None, args=None):
    args = request.args if args is None else args
    raw = args.get(name)
    if raw is None or raw == '':
        return default
    lowered = raw.lower()
    if lowered in TRUE:
        return True
    if lowered in FALSE:
        return False
    raise ValidationError(
        "'%s' must be a boolean" % name,
        {'parameter': name, 'received': raw,
         'allowed': sorted(TRUE | FALSE)})


def str_arg(name, default=None, max_len=255, args=None):
    args = request.args if args is None else args
    raw = args.get(name)
    if raw is None or raw == '':
        return default
    if len(raw) > max_len:
        raise ValidationError(
            "'%s' must be at most %d characters" % (name, max_len),
            {'parameter': name, 'max_length': max_len})
    return raw


def ip_arg(name, default=None, args=None):
    """An address filter. Validated here so a malformed value is a 400,
    not a driver-level error from PostgreSQL's inet type."""
    import ipaddress
    value = str_arg(name, default, max_len=45, args=args)
    if value in (None, default) and value is None:
        return default
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError(
            "'%s' must be a valid IP address" % name,
            {'parameter': name, 'received': value}) from None
    return value


def pagination(default_limit=50, max_limit=MAX_LIMIT):
    """Standard `limit`/`offset` pair used by every collection endpoint."""
    return (int_arg('limit', default_limit, 1, max_limit),
            int_arg('offset', 0, 0, MAX_OFFSET))


def sort_args(allowed, default_sort, default_order='desc'):
    return (choice_arg('sort', allowed, default_sort),
            choice_arg('order', ('asc', 'desc'), default_order))


def json_body(required_keys=()):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValidationError('request body must be a JSON object',
                              {'content_type': request.content_type})
    missing = [k for k in required_keys if k not in body]
    if missing:
        raise ValidationError('missing required field(s)',
                              {'missing': missing})
    return body
