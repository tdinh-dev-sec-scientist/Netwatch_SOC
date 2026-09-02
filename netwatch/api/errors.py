"""
One error contract for the whole API.

Every failure — a bad query parameter, a missing resource, an unhandled
exception — leaves the application as the same JSON object:

    {"error": {"code": "...", "message": "...", "details": {...}},
     "status": 404}

`code` is a stable machine-readable string a client can branch on;
`message` is for a human; `details` carries whatever is specific to that
failure (which parameter, what was allowed). Callers never have to guess
whether a 4xx body is JSON or an HTML error page.
"""

from flask import jsonify


class ApiError(Exception):
    """Base class for every failure the API reports deliberately."""

    status = 400
    code = 'bad_request'

    def __init__(self, message, details=None, status=None, code=None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        if status is not None:
            self.status = status
        if code is not None:
            self.code = code

    def to_response(self):
        payload = {'error': {'code': self.code, 'message': self.message},
                   'status': self.status}
        if self.details:
            payload['error']['details'] = self.details
        return jsonify(payload), self.status


class ValidationError(ApiError):
    status = 400
    code = 'validation_error'


class NotFoundError(ApiError):
    status = 404
    code = 'not_found'


class ConflictError(ApiError):
    status = 409
    code = 'conflict'


class ServiceUnavailable(ApiError):
    status = 503
    code = 'service_unavailable'


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def _api_error(err):
        return err.to_response()

    @app.errorhandler(400)
    def _bad_request(_err):
        return ApiError('malformed request', code='bad_request').to_response()

    @app.errorhandler(404)
    def _not_found(_err):
        return NotFoundError('resource not found').to_response()

    @app.errorhandler(405)
    def _method_not_allowed(err):
        return ApiError('method not allowed for this resource', status=405,
                        code='method_not_allowed',
                        details={'allowed': sorted(getattr(err, 'valid_methods',
                                                           []) or [])}
                        ).to_response()

    @app.errorhandler(500)
    def _server_error(_err):
        return ApiError('internal server error', status=500,
                        code='internal_error').to_response()

    @app.errorhandler(Exception)
    def _unhandled(err):
        # Never leak a stack trace or a driver message to a client; the
        # exception is logged with full detail on the server side.
        app.logger.exception('unhandled error serving request')
        if isinstance(err, ApiError):
            return err.to_response()
        return ApiError('internal server error', status=500,
                        code='internal_error').to_response()
