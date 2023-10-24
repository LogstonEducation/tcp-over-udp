from utils import ones_complement

def test_ones_complement():
    assert ones_complement(int('479e', 16)) == int('b861', 16)
