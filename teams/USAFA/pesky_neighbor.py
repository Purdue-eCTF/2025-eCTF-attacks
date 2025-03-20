#!/usr/bin/env python3
import json
import sys
import traceback


from ectf25.utils.decoder import DecoderIntf
from loguru import logger


def conn():
    r = DecoderIntf(sys.argv[1], timeout=5, write_timeout=5)
    return r


# def equal_timestamps(r: DecoderIntf):
#     frame = bytes.fromhex(frames[1][0]["encoded"])
#     print(r.decode(frame))
#     print(r.decode(frame))


# def per_channel_timestamp(r: DecoderIntf):
#     frame1 = frames[1][1]
#     frame2 = next(
#         frame for frame in frames[0] if frame["timestamp"] > frame1["timestamp"]
#     )
#     print(r.decode(bytes.fromhex(frame2["encoded"])))
#     print(r.decode(bytes.fromhex(frame1["encoded"])))


def playback(r):
    for frame in frames:
        # print(frame)
        # print(bytes.fromhex(frame))
        print(r.decode(bytes.fromhex(frame)))


def main():
    r = conn()
    global frames
    # attacks = [equal_timestamps, per_channel_timestamp]
    frames = ["1cb9a16e46610500010000004962d31a92b7694981f251cb72b00a3b56cbda9629e6fb77dc155ce5789f9264c39be4d6e34422a6cd852bb6690a7197415115a7085ebcab506f903507c010bfbe4b8870c0cf9c9007a31fef2f1475515f69c90370b27a8a548833dddfe528e61b55b8f9be3db10533ae8c4e87038327568de517bf7ecbb5db2b06487aa186e90690157e395f791f4ac8205c44f3f3bdc73f99ea788427a3a0d9cc202789f9f0f6b0ad95cba535fc55ad00694f98dc45417ae71b96bf22326b0bc6a039fc09c200000000e29533359d065a8110bc9b89625afd020a623b6afbfcd4cd21f1318500862ecef3ef55fc391de2434914ceb0f05feffca848b2821291555f5ad5e72255c5b0ff4a11725ab5b7f013361c1e2c9a839820457930e9b75cdc3ddaabdf59e5d5b83198dde76c4d7c02a71f70609c53459a4a34f53a3504f4c23297bb24bbf1c78717e1dfeb8a9d45daead70515880553d0714750c70c7a7fd239ce6fde8562ecf5674dbe2cfaa9741df4cbee28486d78fe1411460a308d43579c84a927ab8923b60ef01f31cfbfbcb217c91b23e5c2019034ed94875b551972555ba4f530ead33a06b44348bc4bf85f25cae2d8f4b50054dab1282f871e041133c525685f3cc6b1c78712d4c999dadcc3bd108dcf200904790ae9ac7a37d7f75dcee63b013f30f3ee8dc3b35abb7fcae41b29c27449665ffb46da980bb7fe5e4e6734cd26c4e6986fb8445a7ff86fea20afd0084d6aec4856",
              "2cb9a16e46610500010000004962d31a92b7694981f251cb72b00a3b56cbda9629e6fb77dc155ce5789f9264c39be4d6e34422a6cd852bb6690a7197415115a7085ebcab506f903507c010bfbe4b8870c0cf9c9007a31fef2f1475515f69c90370b27a8a548833dddfe528e61b55b8f9be3db10533ae8c4e87038327568de517bf7ecbb5db2b06487aa186e90690157e395f791f4ac8205c44f3f3bdc73f99ea788427a3a0d9cc202789f9f0f6b0ad95cba535fc55ad00694f98dc45417ae71b96bf22326b0bc6a039fc09c200000000e29533359d065a8110bc9b89625afd020a623b6afbfcd4cd21f1318500862ecef3ef55fc391de2434914ceb0f05feffca848b2821291555f5ad5e72255c5b0ff4a11725ab5b7f013361c1e2c9a839820457930e9b75cdc3ddaabdf59e5d5b83198dde76c4d7c02a71f70609c53459a4a34f53a3504f4c23297bb24bbf1c78717e1dfeb8a9d45daead70515880553d0714750c70c7a7fd239ce6fde8562ecf5674dbe2cfaa9741df4cbee28486d78fe1411460a308d43579c84a927ab8923b60ef01f31cfbfbcb217c91b23e5c2019034ed94875b551972555ba4f530ead33a06b44348bc4bf85f25cae2d8f4b50054dab1282f871e041133c525685f3cc6b1c78712d4c999dadcc3bd108dcf200904790ae9ac7a37d7f75dcee63b013f30f3ee8dc3b35abb7fcae41b29c27449665ffb46da980bb7fe5e4e6734cd26c4e6986fb8445a7ff86fea20afd0084d6aec4856"]
    attacks = [playback]
    for attack in attacks:
        logger.info(f"Running {attack.__name__}")
        try:
            attack(r)
        except Exception:
            traceback.print_exc()


if __name__ == "__main__":
    main()
