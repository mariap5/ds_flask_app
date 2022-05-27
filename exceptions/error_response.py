class ErrorResponse:
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message

    def to_dict(self):
        return {
            "status_code": self.status_code,
            "message": self.message
        }
