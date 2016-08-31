
class Error(Exception):
    pass


class InvalidEncoding(Error):
    pass


class UnknownMagicNumber(Error):
    pass


class InvalidHeader(Error):
    pass

