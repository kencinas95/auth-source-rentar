from pymongo.errors import DuplicateKeyError


class UnhandledDatasourceError(BaseException):
    def __init__(self, ex: Exception):
        super().__init__(ex)
        self.__cause__ = ex


class UserUnauthorizedError(BaseException):
    pass


class InvalidSessionError(BaseException):
    pass


class InvalidActivationTokenError(BaseException):
    def __init__(self, token: str):
        super().__init__(token)


class UserAlreadyActivatedError(BaseException):
    def __init__(self, uid: str):
        super().__init__(uid)


class UserNotFoundError(BaseException):
    def __init__(self, uid: str):
        super().__init__(uid)


class UserInactiveError(BaseException):
    def __init__(self, uid: str):
        super().__init__(uid)


class DuplicateUserError(BaseException):
    def __init__(self, ex: DuplicateKeyError):
        super().__init__(ex)
        self.key = ex.details["keyPattern"]
