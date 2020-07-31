import abc


class Analyzer:
    """
        abstract class for analyzing the sniffed data
    """
    @abc.abstractmethod
    def analyze(self, raw_data):
        pass

    @abc.abstractmethod
    def report(self):
        pass
