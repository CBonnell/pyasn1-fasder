from pyasn1 import error


class Pyasn1FasderError(error.PyAsn1Error):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
