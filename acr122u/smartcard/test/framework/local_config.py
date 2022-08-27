from smartcard.util import toHexString
expectedReaders = ['Gemalto PC Twin Reader']
expectedATRs = [[59, 167, 0, 64, 24, 128, 101, 162, 8, 1, 1, 82]]
expectedATRinReader = {}
for i in range(len(expectedReaders)):
    expectedATRinReader[expectedReaders[i]] = expectedATRs[i]
expectedReaderForATR = {}
for i in range(len(expectedReaders)):
    expectedReaderForATR[toHexString(expectedATRs[i])] = expectedReaders[i]
expectedReaderGroups = ['SCard$DefaultReaders']
