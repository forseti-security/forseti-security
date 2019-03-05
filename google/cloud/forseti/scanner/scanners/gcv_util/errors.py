from exceptions import Exception


class GCVAddDataError(Exception):
    """GCV Add Data Error."""
    pass


class GCVServerUnavailableError(Exception):
    """GCV Server Unavailable Error."""
    pass


class GCVAuditError(Exception):
    """GCV Audit Error."""
    pass


class GCVResetError(Exception):
    """GCV Reset Error."""
    pass
