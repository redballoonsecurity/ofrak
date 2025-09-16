unsigned int check_des_address(unsigned int address, unsigned int length)
{
    unsigned int end_address = address + length;
    if (address > 0x5FFFFFFF && end_address < 0x6FBFFFFF) {
        return 0;
    }
    if (length > 0xFC000000) {
        return -1;
    }
    return 0;
}
