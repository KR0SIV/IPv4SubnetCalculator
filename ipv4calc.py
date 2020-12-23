from textwrap import wrap
import tkinter as tk
import re


def dec2bin(n):
    if n > 255:
        raise Exception('Octet May not be more than 255')
    return bin(n).replace("0b", "")


def bin2dec(binary):
    decimal, i, n = 0, 0, 0
    while (binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary // 10
        i += 1
    return(str(decimal))


def ip2bin(ipaddr):
    octets = ipaddr.split('.')
    oct1 = dec2bin(int(octets[0])).zfill(8)
    oct2 = dec2bin(int(octets[1])).zfill(8)
    oct3 = dec2bin(int(octets[2])).zfill(8)
    oct4 = dec2bin(int(octets[3])).zfill(8)
    return str(oct1 + '.' + oct2 + '.' + oct3 + '.' + oct4)

def bin2ip(binaddr):
    octets = binaddr.split('.')
    oct1 = bin2dec(int(octets[0]))
    oct2 = bin2dec(int(octets[1]))
    oct3 = bin2dec(int(octets[2]))
    oct4 = bin2dec(int(octets[3]))
    return str(oct1 + '.' + oct2 + '.' + oct3 + '.' + oct4)

def sub2cidr(netmask):
    mask = ip2bin(netmask).replace('.', '')
    count = 0
    for i in mask:
        if i == '1':
            count = count + 1
    return count

def cidr2sub(cidr):
    if int(cidr) > 32:
        raise Exception('CIDR Value May Not Exceed 32 bits')
    empty = ''
    binary = empty.rjust(int(cidr), str(1)).ljust(32, str(0))
    oct1 = wrap(binary, 8)[0]
    oct2 = wrap(binary, 8)[1]
    oct3 = wrap(binary, 8)[2]
    oct4 = wrap(binary, 8)[3]
    return bin2ip(str(oct1 + '.' + oct2 + '.' + oct3 + '.' + oct4))

def totalhosts(netmask):
    binary = ip2bin(netmask).replace('.', '')
    count = 0
    for i in binary:
        if i == '0':
            count = count + 1
    hosts = pow(2, count)
    return str(hosts - 2)

def maskbitcheck(ip, mask):
    for i in ip:
        for m in mask:
            if m == '1':
                i = i
            else:
                i = '0'
            return i

def maxmaskbitcheck(ip, mask):
    for i in ip:
        for m in mask:
            if m == '1':
                i = '1'
            return i

def octcheck(ipoct, maskoct, max=False):
    if max == True:
        bit1 = maxmaskbitcheck(ipoct[0], maskoct[0])
        bit2 = maxmaskbitcheck(ipoct[1], maskoct[1])
        bit3 = maxmaskbitcheck(ipoct[2], maskoct[2])
        bit4 = maxmaskbitcheck(ipoct[3], maskoct[3])
        bit5 = maxmaskbitcheck(ipoct[4], maskoct[4])
        bit6 = maxmaskbitcheck(ipoct[5], maskoct[5])
        bit7 = maxmaskbitcheck(ipoct[6], maskoct[6])
        bit8 = maxmaskbitcheck(ipoct[7], maskoct[7])
        return int(bit1 + bit2 + bit3 + bit4 + bit5 + bit6 + bit7 + bit8)

    bit1 = maskbitcheck(ipoct[0], maskoct[0])
    bit2 = maskbitcheck(ipoct[1], maskoct[1])
    bit3 = maskbitcheck(ipoct[2], maskoct[2])
    bit4 = maskbitcheck(ipoct[3], maskoct[3])
    bit5 = maskbitcheck(ipoct[4], maskoct[4])
    bit6 = maskbitcheck(ipoct[5], maskoct[5])
    bit7 = maskbitcheck(ipoct[6], maskoct[6])
    bit8 = maskbitcheck(ipoct[7], maskoct[7])
    return int(bit1 + bit2 + bit3 + bit4 + bit5 + bit6 + bit7 + bit8)

def masktrail(maskoct):
    try:
        trailing = re.findall('(?:^.*1)(.*0)', maskoct)
        empty = ''
        return str(maskoct.replace(trailing[0], empty.ljust(len(trailing[0]), '1')))
    except:
        return '11111111'

def hostrange(ipaddr, netmask):
    ip = ip2bin(ipaddr).split('.')
    mask = ip2bin(netmask).split('.')
    soct1 = bin2dec(octcheck(ip[0], mask[0]))
    soct2 = bin2dec(octcheck(ip[1], mask[1]))
    soct3 = bin2dec(octcheck(ip[2], mask[2]))
    soct4 = bin2dec(octcheck(ip[3], mask[3]) + 1)
    startip = str(soct1 + '.' + soct2 + '.' + soct3 + '.' + soct4)
    if mask[0] != '11111111':
        eoct1 = bin2dec(octcheck(ip[0], masktrail(mask[0]), max=True))
    else:
        eoct1 = bin2dec(octcheck(ip[0], masktrail(mask[0])))
    if mask[1] != '11111111':
        eoct2 = bin2dec(octcheck(ip[1], masktrail(mask[1]), max=True))
    else:
        eoct2 = bin2dec(octcheck(ip[1], masktrail(mask[1])))
    if mask[2] != '11111111':
        eoct3 = bin2dec(octcheck(ip[2], masktrail(mask[2]), max=True))
    else:
        eoct3 = bin2dec(octcheck(ip[2], masktrail(mask[2])))
    if mask[3] != '11111111':
        eoct4 = bin2dec(octcheck(ip[3], masktrail(mask[3]), max=True) -1)
    else:
        eoct4 = bin2dec(octcheck(ip[3], masktrail(mask[3])))
    endip = str(eoct1 + '.' + eoct2 + '.' + eoct3 + '.' + eoct4)
    return startip + ' ' + endip



#ip = '10.0.0.1'
#mask = '255.0.0.0'

#print(hostrange(ip, mask))
#print(totalhosts(mask))
#print(hostrange(ip, cidr2sub(8)))
#print(cidr2sub(8))
#print(ip2bin('192.168.122.1'))
#print(bin2ip('11000000.10101000.01111010.00000001'))

def calculate(ip, mask, cidr):
    if cidr != '':
        maskentry.insert(index=0, string=cidr2sub(cidr))
    if mask != '':
        cidrentry.insert(index=0, string=sub2cidr(mask))
    try:
        rangelabel.configure(text=hostrange(ip, mask))
    except:
        rangelabel.configure(text=hostrange(ip, cidr2sub(cidr)))

def clearvalues():
    ipentry.delete(0, 'end')
    cidrentry.delete(0, 'end')
    maskentry.delete(0, 'end')
    rangelabel.configure(text='')

window = tk.Tk()

window.title('IPv4 Subnet Calculator')

iplabel = tk.Label(text='IP Address: ')
iplabel.grid(column=0, row=0)

ipentry = tk.Entry()
ipentry.grid(column=1, row=0)

cidrlabel = tk.Label(text='CIDR: ')
cidrlabel.grid(column=2, row=0)

cidrentry = tk.Entry()
cidrentry.grid(column=3, row=0)

masklabel = tk.Label(text='Mask: ')
masklabel.grid(column=0, row=1)

maskentry = tk.Entry(text='')
maskentry.grid(column=1, row=1)

calcbutton = tk.Button(text='Calculate', command=lambda: calculate(ipentry.get(), maskentry.get(), cidrentry.get()))
calcbutton.grid(column=0, row=3)

clearbutton = tk.Button(text='Clear Values', command=clearvalues)
clearbutton.grid(column=1, row=3)


rangelabel = tk.Label(text='')
rangelabel.grid(column=2, row=3)




window.mainloop()
