# JFFS2 Dump utility

This python script dumps the content of the jffs2 image to disk

# Conversion of Endianness

In some cases you need to convert the image Endianess. Given a JFFS2 image in Big Endian Byte Order has to be converted to little Endian Byte-Order
At first you need the mtd-utils package installed on your Linux Box

    # sudo apt-get install mtd-utils

Then you can convert the Endianess

    # jffs2dump -v -b -r  -edum.bin uJFFS2.bin



You may need to fix some sporadic strange errors about Wrong bitmask at offset 0x0....  If you only get those messages you have done something completely wrong.

    ....
    Wrong bitmask  at  0x00010ba8, 0xf78a
    ....

I fixed them with the help of sumtool

   sumtool -l -i dum.bin -o dum.sum -v

# Usage
It is darn simple to use

    ./jffs2-dump.py dum.sum
