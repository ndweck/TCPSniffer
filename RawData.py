import abc


class RawData:
    """
    abstract class for holding raw data
    """
    @abc.abstractmethod
    def add(self, data):
        pass
