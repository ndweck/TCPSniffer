from RawData import RawData


class PacketsStructure(RawData):
    """
    concrete class for holding the raw data in memory in a list data structure
    """
    packetDataList = []

    def __init__(self):
        self.ptr = 0

    def add(self, data):
        """
        appends the data to the end of the list
        :param data: the data to save
        :return: None
        """
        self.packetDataList.append(data)

    def __iter__(self):
        self.ptr = 0
        return self

    def __next__(self):
        if self.ptr == len(self.packetDataList):
            raise StopIteration
        x = self.packetDataList[self.ptr]
        self.ptr += 1
        return x
