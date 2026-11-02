#!/usr/bin/env python3
"""Export byte-pinned node #94 call-address provenance without executing it."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_SIZE = 91774280

# Bounds and hashes are fixed expectations; exported coordinates come from FDEs.
FUNCTIONS = [
    (0x1f9b220, 0x1f9b2b3, '500058d18af5044a77259adb072a013e8d98a668de7ee635c74f28ccb775f3f7'),
    (0x1f6e9f0, 0x1f6f2fa, '6f95912c98fb197171c7b81c57d19ad91baa9cf61040b5b02972baf5763510e5'),
    (0x1e68cc0, 0x1e690fb, '28527f38c20e3f4985f972aca84b1f67fe155ce655ded6f15b47fe44ebfc5a8f'),
    (0x1b2af40, 0x1b2b1b9, '0db1b3c365d6eba7778de299012740bafb0373594cf95c837de09748906f9133'),
    (0x1bda270, 0x1bdce65, '4e2566bbfa9863dd291ef04bfdc4900c6cf4d3956098c84a5ff88f31037eb577'),
    (0x21a0f30, 0x21a10fe, '2a204adcc9c203b33eb5b896c57b0dfb5eb1e84f819f178258555eb46e8c95a0'),
    (0x21a1100, 0x21a135a, 'ec1f756ca9ef65139376dc4bd6f7909649bb89e1570a0392fa648a73f1225b45'),
    (0x2523c40, 0x2523daa, 'b5bb43a29ee16f78c595c9386e2383d93a7814f1c279656b4f8fe794ff5ba887'),
    (0x26a9800, 0x26a99b5, 'fa1ddcc9ffcc85be11b01f3646a3943473adcd274e80f601dd9447c726804aaf'),
    (0x28070b0, 0x28076e1, 'fb4d998fc4459e55dfb9a87d9d1165862f4997691d64eb6f966802fbd900210b'),
    (0x280fb50, 0x280fbb8, 'adc42b64fde0084bb2a57d49ac14bcaa6f8b8611c17dd7fee05dc746210ca576'),
    (0x2883a60, 0x2883acb, 'd47dc12bb55085aa2921e7f8a1756f8f55e9dfbd416e502c7f2e2387441e1687'),
    (0x27bff10, 0x27c0cf8, '3c4364737a9956bc113c3b7cc2d7930a4be6ce27b9a3990a84c4dd43d883979f'),
    (0x247db80, 0x247e720, 'fd9f87e878a3ccbff3c2d49be0dcd14a25e7b3a78a2751fd7da2dec1e9b07f83'),
    (0x247e720, 0x247fd15, 'c808d6fb0ee31ca585f2b6d35541fb4f97c73bfca3f6b04933e4438ff2d0b699'),
    (0x4e59140, 0x4e59344, 'ab7654882da9a047915fe128dcf60b0c46cc9e6e0a1b0e8e56e4e6aae2dee368'),
    (0x4e5c710, 0x4e5d582, '798510655209601d7b08b95b2cb33d294ea749e36ca01efa91ea9e1fc9d23736'),
    (0x4e5d830, 0x4e5dbad, 'b999c9a8fd7fcbbea6d1b4706776a8f239b8f22da8d19040f1b1f5d7542a39da'),
    (0x24cc0c0, 0x24cca98, '8d6187367e04a3d20479449f9c9a64c09166675435fc20da50106fbd53f23361'),
]
WINDOWS = [
    ('descriptor-adapter', 0x1f9b220, 0x1f9b275, 'ae81dfb039b043c0883ff835afc58cacf886fa68a698188d84f69e185ee57fb6'),
    ('entry-params', 0x1f6e9f0, 0x1f6ea63, '95cd08f116519efbc583c02a0fe4b6d025811b5278d5b84e2501ceb463ee7296'),
    ('entry-request', 0x1f6eb75, 0x1f6ebd8, 'ec80af7312b7dbf09e89d4b2b2274ed6ee2aef8140b1cfe7807555505eb6a64f'),
    ('entry-extra-arguments', 0x1f6ebd8, 0x1f6ed40, '776f845f799554995cbd69c43a8125bcd234afe795801528713b3c48234e3e94'),
    ('entry-pass-object', 0x1f6ed36, 0x1f6edad, 'b1bf86289a88c7bd137a6346bcf1a8ed3407420cc93fb69bcbb038159b41df7b'),
    ('array-open', 0x1e68ce5, 0x1e68d98, 'e47b7e24e700eee6ecb808bfa5df138390c4c8a099118eac2a68f0058fab9524'),
    ('array-success-a', 0x1e68ec6, 0x1e68f09, 'feb1f41bae37c94a8bdfaa3b30fd700348b3f70f7d00863c910ea3555e71930b'),
    ('array-success-b', 0x1e68f9a, 0x1e68fcd, 'fb74ed7572716d0b32ddbea783751a9d53cfe0583966fa1f30199e20ced76603'),
    ('array-copy', 0x1e6901a, 0x1e6907f, '0a09ad2c6ca539175b2ba7d0f37186ae1538477976f4937767b90dc2e01e03f1'),
    ('array-visitor', 0x1b2afbe, 0x1b2b020, '88268f705055eac17014c5e4fa6ab00d46f925ad6c5e4a7348fe35d3de32fe5a'),
    ('array-visitor-copy', 0x1b2b020, 0x1b2b075, '4da8248a126f3f2de41218b54c7f3863089aef047d6cc5b60d68b92570f7dedd'),
    ('array-visitor-return', 0x1b2b09e, 0x1b2b107, '6020de92ed30c1f30a809d1bcd5a3225dbf082cc663b748308511f6819f45f75'),
    ('key-borrowed', 0x21a0f30, 0x21a0f60, '088999d3beb335182dcc76ac0dc96c7fcd13f67b5f60a7d2ed88792f06883e6e'),
    ('key-owned', 0x21a1100, 0x21a113f, '5391af14cae10ca2109fad769a526501758784ef84face3f54ebd9870d3ed85d'),
    ('object-field-dispatch', 0x1bda4d9, 0x1bda5cb, '9d92e9179fa27bb72aaf0adf1cd2ca131605405975fbfee7743fa01c417782bd'),
    ('object-duplicate-guard', 0x1bda952, 0x1bda9ac, '541768545a1651330a27afd3e260f933363779191ee21e09ac4a50559f126e62'),
    ('object-to-value', 0x1bdb066, 0x1bdb0f5, '4beb2f241a43d8920ae9f0c29b9096ef8601231f5f62c2ecfda24583a6106056'),
    ('object-default', 0x1bdb5b1, 0x1bdb5de, 'f564cb4c642dc57f382525ca0607120e2207c9d2c630f5c43520c7492c5ad201'),
    ('object-default-alt', 0x1bdb6ad, 0x1bdb6bf, 'b9502d5b7a78390c27c283b949201dc743a1ae243dff3363a83860ed74323227'),
    ('object-save-tag', 0x1bdb7f0, 0x1bdb80a, '5269b58247c261430c23c9c6b076847af1e9c9040f8cd6e28dd12e80c1343bda'),
    ('object-save-tag-alt', 0x1bdb858, 0x1bdb861, '20f13fc0a8abdee14ac95e6dac63cd3a058814c249fd855a5591a7254b4d0c29'),
    ('object-pack-head', 0x1bdbb33, 0x1bdbb51, '0f16d0f8ed5b7e67649d0c890d132fb8ae8271576796e889cbc2781c7d863cdc'),
    ('object-pack-tail', 0x1bdbd4b, 0x1bdbd85, '8b2e5bf499c5fb76896fab8e04d5c7006bc7cdf90505e9387fbfa0c0acf76429'),
    ('object-bulk-forward', 0x1bdb49d, 0x1bdb4de, 'd96c32d200310121373579696ce6e620cec06aeb007bd42a9d5e7b3bbafc0ebe'),
    ('object-return', 0x1bdb527, 0x1bdb555, '96f2f565767dcaebf7299c9d300dd83a9eb5082f7ea0dbeecabd30daefded82f'),
    ('object-duplicate-error', 0x1bdc4f2, 0x1bdc533, 'bdc66822e914ad41d0d0e230c829d89dd42fcbe7a25c34a947c1daba2d760ba1'),
    ('optional-scan-null', 0x2523c40, 0x2523d23, '80f93b20acaf50e0fd2355dfc5a95b5aee0e4180f91ada30fe7ce14e2c7f342f'),
    ('optional-parse-result', 0x2523d23, 0x2523d69, 'b5228ba9086d3777f5f41a8012f6c0e1b9160a842d5655c3a5eff3bca6f5c56d'),
    ('optional-invalid-null', 0x2523d69, 0x2523d9d, 'bec0fbe950a3e4c4a6f0b0f9abd31bdccdc3a92250af268284ef99bf09c1c97b'),
    ('optional-adapter-null', 0x26a986c, 0x26a98e5, '84a3c62970f9bcddef2003946e1f0a03ae97b012f47dee618bf0321d41b162d0'),
    ('optional-adapter-some', 0x26a98e5, 0x26a997f, '5cd80d1f04c6625200e99e62eeb3a13058057a07019721a929cc1b6abfd7d475'),
    ('address-json-string', 0x2807266, 0x28072cc, 'f7d3ce859ca6cc051c42ae4942ff70c337378365855292d627fdd51b69bb1156'),
    ('address-json-result', 0x28072cc, 0x2807300, '1f62386a65a340ed16a5634ea66077fcd489281ec0571459914c3a305d23b860'),
    ('decode-owned', 0x280fb50, 0x280fbb8, 'adc42b64fde0084bb2a57d49ac14bcaa6f8b8611c17dd7fee05dc746210ca576'),
    ('decode-borrowed', 0x2883a60, 0x2883acb, 'd47dc12bb55085aa2921e7f8a1756f8f55e9dfbd416e502c7f2e2387441e1687'),
    ('adapter-request-save', 0x27bff10, 0x27bff48, '41e9cbe13f34badf51b793c31d8f45f48a21e02cfdfed1b35ac96a3ae5f6a963'),
    ('adapter-request-forward', 0x27c024f, 0x27c026a, '7195db4f9ed39baf0d8846c2833a55ce998a85b6c6066ddf0c8e0b4878871baf'),
    ('adapter-builder-args', 0x27c02a4, 0x27c031e, '11a86aa7f8fec42dd510d9ff68172a0d7d79f628a58e89a0038f7cd9be52d593'),
    ('prepare-precheck', 0x247db80, 0x247dc11, 'b5cc4f662202212212a32ca215c6ab1cf9d72d69e5a3b2ca54f6c98cda6bce0d'),
    ('prepare-env-call', 0x247dee9, 0x247dfa6, '7da7134650577ce275c1ba843ff3e8297b16a8392619a0834dffaea3476ce226'),
    ('prepare-zero-cap', 0x247e348, 0x247e393, 'b222d88dccef3eb14817c2d904c0217ac3409a4819d46406da8d6c9266165fce'),
    ('prepare-check-error', 0x247e393, 0x247e3a3, '238f5a6f2ea00837710817fe32f19b201cc1b5f27ba27e9f4213b11de2e4f580'),
    ('env-tag-and-key-input', 0x247e783, 0x247e7d3, 'fa15777d0a985f8b534ee10628a656a438a70d81ab3f543540e3eb00b426a85b'),
    ('env-tag-choice', 0x247ee6f, 0x247ee98, '70651c7338ef8e3d060a0d1a4e9f47cb4425dfac32bc5bc7cb3f40a75ed35d69'),
    ('env-tag-clear', 0x247ef4a, 0x247ef5d, '4b46bd8a00637c40eefd007ced3e427cdd1f30c1e8e57ef2c9ee54d451de5e2c'),
    ('env-address-pack', 0x247f5dd, 0x247f607, '7af40c57e6fe15a316dc10acdd230ba57a8fb413a83e0d1060f482181ebe0aae'),
    ('env-stage-copy', 0x247f825, 0x247f840, '540451e048200224ec9d1e0b0d16f18bd6aae7f6fd3497443f3d78e9ed090764'),
    ('env-copy-final-tail', 0x247f90f, 0x247f92d, '763b533be7cd6aa8b79d735841d313b7698ffef1f21c976922d89ceaae5ec69d'),
    ('env-allocation', 0x247fa11, 0x247fa4d, '963c5ddb4eee8dd1fddb7475fbe7f7827ad79be4fb9162927b5daea92afea9ec'),
    ('env-alloc-failure', 0x247fa5f, 0x247fa71, '1079ddaa938ecb39c4532caa02f56f4b52fad6a5cae899d8c982956a816a0aaf'),
    ('adapter-engine-cleanup', 0x27c031e, 0x27c036c, '407ca39cd52efbf49998be539df7659b35f7a82eed2d888d38af525ac584c37b'),
    ('adapter-prepare-failure', 0x27c036c, 0x27c0410, 'bd678b3635f4484c2ad56e03f732cbda733b8e20761c267678a3f2cabd3cc446'),
    ('adapter-result-copies', 0x27c051e, 0x27c0584, 'b48cae06fd0edcc1a9b86d7f1c6a6c9c1d96bd44ca7625af19a8a459c0750cf0'),
    ('adapter-result-route', 0x27c06c0, 0x27c0735, '26677c95737f56da21aa6d2a93f1ff64d88f273c272071c35c64267b89f02283'),
    ('adapter-result-convert', 0x27c0898, 0x27c08f3, '215020bc623cc6151cf361f967290181da0280554b05424ad62f551193e07cc8'),
    ('adapter-result-error', 0x27c0986, 0x27c09da, '62d9f61fee4786ffcae84d628306bf17b4f8faa700eb284d5c1339903785a920'),
    ('rpc-result-wrap', 0x1f6edad, 0x1f6eec7, 'fc2124b469a5bfb2bbc98da56543928561bcc78dbd1b4b18ed2129df47023265'),
    ('result-variant', 0x4e59140, 0x4e591d1, '3d5075a398420034ae86178d1dac499cebc83c5b7dce7afc1385a97a20389467'),
    ('result-error-tags', 0x4e591d1, 0x4e59264, 'd35cf4673fc488686de12fc200d7553eaea304b4512ec3a56900de23efb900a8'),
    ('error-dispatch', 0x4e5c710, 0x4e5c73a, '5bc4f3d3f9977bfcc6d9b98c00f584c6f703200b4c39cdb3a68fc261272cfb8c'),
    ('error-subtype-call', 0x4e5cc7b, 0x4e5cccd, '7e519c44ef85c7d16fcda1e30320dba8bcfc24a554e98f895b915c0868e02b90'),
    ('error-subtype-guards', 0x4e5d830, 0x4e5d851, 'b24040b2e7002da263674669dcd17bc2c3b453e10d627e06633edc2eecce3599'),
    ('error-code', 0x4e5d96e, 0x4e5d9c2, '86260f81735a06a432a2707b520b4b5e8ccea8f8030e77cafff38b9065b85869'),
    ('error-emit', 0x4e5d9fc, 0x4e5da50, '7d2e3a6466006b20836a7a05036e4a5744e0095eda578a1b7045916c2c436bee'),
    ('error-formatter-failure', 0x4e5dac9, 0x4e5daf3, 'd1d556fb94009dc3b2a8361f2e9776b69ad62139da3363ab53cda88dc8d55dc9'),
    ('rpc-wrap-dispatch', 0x24cc0df, 0x24cc1c7, '8393062b53fb21cc685ac5489337b6211a19eb0b95ca8b4d6d25a75b7ea7696e'),
    ('rpc-wrap-code-arm', 0x24cc7a8, 0x24cc7b5, 'da8583178a70ecd7e017c1019bc8dda1d22288173709b88944b2371d076899bc'),
    ('rpc-wrap-serialize', 0x24cc241, 0x24cc269, '2098eaaa01529058c7036efbfc5e7a21e3cf48f2c7bd9c989916bbef2f8c1a43'),
    ('rpc-wrap-output', 0x24cc359, 0x24cc39e, '1a63c5a744fbb716079318bd555374abf7b665cabb09bbcf55b077c8a0f5d43e'),
    ('rpc-wrap-allocation-failure', 0x24cc820, 0x24cc835, 'f590dacff63a3aea0d4d551d9f8e2ba12ed810a2b63ea961a362bc70c32973ab'),
]
EDGES = [
    (0x21a0f3b, 'jcc', 0x21a10e6),
    (0x21a0f56, 'jcc', 0x21a10e6),
    (0x21a1116, 'jcc', 0x21a1323),
    (0x21a1131, 'jcc', 0x21a12e2),
    (0x1bda956, 'jcc', 0x1bdc4f2),
    (0x1bda98c, 'jcc', 0x1bdb066),
    (0x1bdb06a, 'jcc', 0x1bdc919),
    (0x1bdb096, 'jcc', 0x1bdc262),
    (0x1bdb5ba, 'jcc', 0x1bdb6bc),
    (0x1bdb6b6, 'jcc', 0x1bdb5c0),
    (0x1e68ced, 'jcc', 0x1e68e22),
    (0x1e68d04, 'jcc', 0x1e68dd1),
    (0x1e68db2, 'jcc', 0x1e68ec6),
    (0x1b2aff6, 'jcc', 0x1b2b020),
    (0x1f6ea5d, 'jcc', 0x1f6eb5d),
    (0x1f6ebb7, 'jcc', 0x1f6efd1),
    (0x1f6ebf9, 'jcc', 0x1f6ebff),
    (0x1f6ec33, 'jcc', 0x1f6f05a),
    (0x1f6ec89, 'jcc', 0x1f6ec8f),
    (0x1f6ecb6, 'jcc', 0x1f6f0cf),
    (0x1f6ed00, 'jcc', 0x1f6ed06),
    (0x1f6ed3a, 'jcc', 0x1f6f163),
    (0x1f6ebe8, 'call', 0x1e67fb0),
    (0x1f6ec78, 'call', 0x1e67a80),
    (0x1f6ecef, 'call', 0x1e67d60),
    (0x2523cb0, 'jcc', 0x2523d23),
    (0x2523cdf, 'jcc', 0x2523d92),
    (0x2523cfc, 'jcc', 0x2523d92),
    (0x2523d13, 'jcc', 0x2523d92),
    (0x2523d32, 'jcc', 0x2523d4a),
    (0x26a98f4, 'jcc', 0x26a9903),
    (0x2807141, 'jcc', 0x2807266),
    (0x280729c, 'jcc', 0x28072a7),
    (0x28072b3, 'jcc', 0x28072bc),
    (0x28072c6, 'jcc', 0x28075bd),
    (0x280fb71, 'jcc', 0x280fb97),
    (0x2883a81, 'jcc', 0x2883aa4),
    (0x247dbc1, 'jcc', 0x247dbd7),
    (0x247df79, 'jcc', 0x247e061),
    (0x247df8f, 'jcc', 0x247e348),
    (0x247e36e, 'jcc', 0x247df95),
    (0x247e39d, 'jcc', 0x247e44f),
    (0x247ee74, 'jcc', 0x247ef55),
    (0x247ef4f, 'jcc', 0x247ee7a),
    (0x247fa1f, 'jcc', 0x247fa5f),
    (0x27c02ef, 'jcc', 0x27c036c),
    (0x1f9b270, 'call', 0x1f6e9f0),
    (0x1f6eb98, 'call', 0x1e68cc0),
    (0x1f6eda8, 'call', 0x27bff10),
    (0x1e68d93, 'call', 0x1b2af40),
    (0x1b2afdb, 'call', 0x1bda270),
    (0x1bda531, 'call', 0x21a0f30),
    (0x1bda51f, 'call', 0x21a1100),
    (0x1bdb089, 'call', 0x2523c40),
    (0x2523d28, 'call', 0x26a9800),
    (0x26a98ea, 'call', 0x28070b0),
    (0x28072b5, 'call', 0x280fb50),
    (0x28072bc, 'call', 0x2883a60),
    (0x247df6d, 'call', 0x247e720),
    (0x27c02d6, 'call', 0x247db80),
    (0x27c0319, 'call', 0x247fd20),
    (0x247dbb4, 'jcc', 0x247dbd7),
    (0x1f6edd5, 'jcc', 0x1f6ede6),
    (0x1f6ee84, 'call', 0x24cc0c0),
    (0x27c032f, 'jcc', 0x27c033f),
    (0x27c0353, 'jcc', 0x27c044d),
    (0x27c06c3, 'jcc', 0x27c0735),
    (0x27c08bd, 'jcc', 0x27c08f3),
    (0x27c08ee, 'jmp', 0x27c09cd),
    (0x27c0730, 'jmp', 0x27c09da),
    (0x4e5916b, 'jcc', 0x4e591a7),
    (0x4e59171, 'jcc', 0x4e591d1),
    (0x4e5918a, 'jcc', 0x4e591fa),
    (0x4e591c6, 'jcc', 0x4e59264),
    (0x4e591ea, 'jcc', 0x4e5923d),
    (0x4e591f3, 'jcc', 0x4e59251),
    (0x4e5d846, 'jcc', 0x4e5d8a3),
    (0x4e5d84b, 'jcc', 0x4e5d96e),
    (0x4e5d9a5, 'jcc', 0x4e5d9b6),
    (0x4e5d9aa, 'jcc', 0x4e5d9bd),
    (0x4e5d9b4, 'jcc', 0x4e5d9c2),
    (0x4e5da0e, 'jcc', 0x4e5dac9),
    (0x24cc0f5, 'jcc', 0x24cc820),
    (0x24cc131, 'jcc', 0x24cc1ae),
    (0x24cc263, 'jcc', 0x24cc359),
    (0x24cc7b0, 'jmp', 0x24cc135),
    (0x24cc25b, 'call', 0x2977ac0),
]

ROLES = {
    0x1f9b220: 'descriptor adapter and retained-reference release',
    0x1f6e9f0: 'request argument routing and adapter call',
    0x1e68cc0: 'first array argument extraction',
    0x1b2af40: 'object parsing adapter and return assembly',
    0x1bda270: 'request-object field dispatch and result assembly',
    0x21a0f30: 'borrowed field-name classifier',
    0x21a1100: 'owned field-name classifier',
    0x2523c40: 'nullable address field and error wrapper',
    0x26a9800: 'optional parsed-value adapter',
    0x28070b0: 'address-shaped JSON value parser',
    0x280fb50: 'owned string fixed-width decoder adapter',
    0x2883a60: 'borrowed string fixed-width decoder adapter',
    0x27bff10: 'request-to-preparation and engine handoff',
    0x247db80: 'preparation gates and environment result forwarding',
    0x247e720: 'request-to-environment conversion and allocation',
    0x4e59140: 'returned execution variant to 32-byte result or tagged error',
    0x4e5c710: 'error variant dispatcher',
    0x4e5d830: 'selected error subtype to packed error code',
    0x24cc0c0: 'response wrapper, error-kind switch and serialization boundary',
}
BOUNDARY_WINDOWS = set()
RELA_EXPECTED = {
    0x5691888: (8, 0x1f9b220),
    0x5691890: (8, 0x1f6e9f0),
    0x5691898: (8, 0x1f6e9f0),
    0x57705c0: (8, 0x156e650),
    0x5770930: (8, 0x4e5c710),
    0x5774eb0: (8, 0x4e59140),
    0x5776e78: (8, 0x4e5d830),
    0x5776e58: (8, 0x4e5a0d0),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_digest(data):
    require(len(data) == TARGET_SIZE and hashlib.sha256(data).hexdigest() == TARGET_SHA256,
            'node #94 size or SHA-256 mismatch')


def va_offset(secs, va, size):
    """Find exactly one allocated, file-backed section containing the whole range."""
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            'invalid virtual range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'virtual range has no unique file-backed section')
    sec = matches[0]
    return sec['offset'] + va - sec['address']


class Image:
    def __init__(self, data, secs):
        self.data = data
        self.secs = secs

    def read(self, va, size):
        off = va_offset(self.secs, va, size)
        raw = self.data[off:off + size]
        require(len(raw) == size, 'truncated virtual range')
        return bytes(raw)

    def offset(self, va, size):
        return va_offset(self.secs, va, size)


def window_ok(raw, expected):
    require(hashlib.sha256(raw).hexdigest() == expected, 'semantic window changed')


def get_operand(image, va, prefix, width=4):
    prefix = bytes.fromhex(prefix)
    raw = image.read(va, len(prefix) + width)
    require(raw.startswith(prefix), 'unsupported operand shape')
    return int.from_bytes(raw[len(prefix):], 'little')


def relative_edge(raw, site):
    """Decode only the explicitly selected rel8/rel32 x86 control shapes."""
    require(len(raw) >= 2, 'truncated relative edge')
    if raw[0] in (0xe8, 0xe9):
        size, kind, delta, cond = 5, ('call' if raw[0] == 0xe8 else 'jump'), 1, ''
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, kind, delta, cond = 6, 'jcc', 2, raw[1] & 15
    elif 0x70 <= raw[0] <= 0x7f:
        size, kind, delta, cond = 2, 'jcc', 1, raw[0] & 15
    elif raw[0] == 0xeb:
        size, kind, delta, cond = 2, 'jump', 1, ''
    else:
        raise ValueError('unsupported relative edge opcode')
    require(len(raw) >= size, 'truncated relative edge')
    displacement = int.from_bytes(raw[delta:size], 'little', signed=True)
    return {'kind': kind, 'condition': cond, 'site': site, 'fallthrough': site + size,
            'target': site + size + displacement, 'bytes': raw[:size].hex()}


def checked_edge(raw, site, kind, expected):
    row = relative_edge(raw, site)
    actual_kind = 'jmp' if row['kind'] == 'jump' else row['kind']
    require(actual_kind == kind and row['target'] == expected, 'relative edge changed')
    return row


def rip_target(image, va, prefix):
    prefix = bytes.fromhex(prefix)
    raw = image.read(va, len(prefix) + 4)
    require(raw.startswith(prefix), 'unsupported RIP-relative shape')
    return va + len(raw) + int.from_bytes(raw[-4:], 'little', signed=True)


def named_section(secs, name):
    candidates = [s for s in secs if s['name'] == name and s['type'] != 8]
    require(len(candidates) == 1, 'missing or duplicate file-backed section')
    return candidates[0]


def check_relative_rela(raw, expected_slot, expected_addend):
    require(len(raw) == 24, 'invalid relative relocation length')
    slot, info, addend = struct.unpack('<QQq', raw)
    require(slot == expected_slot and info == 8 and addend == expected_addend,
            'unexpected relative relocation')
    return slot, info, addend


def relocations(data, secs):
    rela = named_section(secs, '.rela.dyn')
    require(rela['size'] % 24 == 0, 'invalid RELA size')
    requested = set(RELA_EXPECTED) | {0x576dfe0}
    found = {}
    for offset in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot not in requested:
            continue
        require(slot not in found, 'duplicate selected relocation')
        found[slot] = (info, addend, offset, bytes(data[offset:offset + 24]))
    require(set(found) == requested, 'selected relocation missing')
    rows = []
    for slot in sorted(requested):
        info, addend, offset, raw = found[slot]
        typ, symbol = info & 0xffffffff, info >> 32
        name = ''
        symbol_offset, symbol_raw, name_bytes = None, '', ''
        if slot in RELA_EXPECTED:
            require(RELA_EXPECTED[slot][0] == 8, 'unexpected expected relocation type')
            check_relative_rela(raw, slot, RELA_EXPECTED[slot][1])
        else:
            require(typ == 6 and symbol != 0 and addend == 0, 'unexpected copy-call relocation')
            syms, strings = named_section(secs, '.dynsym'), named_section(secs, '.dynstr')
            symbol_offset = syms['offset'] + 24 * symbol
            require(symbol_offset + 24 <= syms['offset'] + syms['size'], 'dynamic symbol outside section')
            name_offset = struct.unpack_from('<I', data, symbol_offset)[0]
            require(name_offset < strings['size'], 'dynamic string outside section')
            start = strings['offset'] + name_offset
            end = data.find(b'\0', start, strings['offset'] + strings['size'])
            require(end >= start, 'unterminated dynamic symbol')
            name_bytes = bytes(data[start:end]).hex()
            symbol_raw = bytes(data[symbol_offset:symbol_offset + 24]).hex()
            name = bytes(data[start:end]).decode('ascii')
            require(name == 'memcpy', 'copy-call symbol changed')
        rows.append({'slot': slot, 'type': typ, 'symbol_index': symbol, 'symbol': name,
                     'addend': addend, 'file_offset': offset, 'raw': raw.hex(),
                     'symbol_file_offset': symbol_offset, 'symbol_raw': symbol_raw, 'name_bytes': name_bytes})
    return rows


def table_rows(image, name, base, count, expected_interval):
    rows = []
    for index in range(count):
        slot = base + index * 4
        raw = image.read(slot, 4)
        target = base + int.from_bytes(raw, 'little', signed=True)
        require(expected_interval[0] <= target < expected_interval[1], 'relative table target outside body')
        rows.append({'table': name, 'index': index, 'slot': slot, 'raw': raw.hex(), 'target': target})
    return rows


def derive_flow(image, tables, relas):
    """Derive the selected byte moves and constants from pinned instruction forms."""
    tag_input = get_operand(image, 0x247e7a9, '410fb686')
    key_input = get_operand(image, 0x247e7c3, '410f1086')
    key_input_tail = get_operand(image, 0x247e7b5, '418b86')
    tag_staging = get_operand(image, 0x247f5e1, '4088b424')
    key_staging = get_operand(image, 0x247f5ff, '0f118c24')
    key_staging_tail = get_operand(image, 0x247f5f0, '89b424')
    copy1_src = get_operand(image, 0x247f825, '488db424')
    copy1_dst = get_operand(image, 0x247f82d, '488dbc24')
    copy1_len = get_operand(image, 0x247f835, 'ba')
    copy2_src = get_operand(image, 0x247f90f, '488db424')
    copy2_dst = get_operand(image, 0x247f917, '488dbc24')
    copy2_len = get_operand(image, 0x247f926, 'ba')
    env_base = get_operand(image, 0x247fa24, '488db424')
    env_size = get_operand(image, 0x247fa2c, 'ba')
    obj_base = get_operand(image, 0x1bdb4a5, '488db424')
    obj_tag = get_operand(image, 0x1bdbd50, '888424')
    obj_parts = [
        (get_operand(image, 0x1bdbb4a, '898c24'), 4),
        (get_operand(image, 0x1bdbb3b, '66898c24'), 2),
        (get_operand(image, 0x1bdbd5f, '48898424'), 8),
        (get_operand(image, 0x1bdbd7e, '898c24'), 4),
        (get_operand(image, 0x1bdbd76, '66898424'), 2),
    ]
    require(all(b == a + width for (a, width), (b, _) in zip(obj_parts, obj_parts[1:])),
            'object payload pieces are not consecutive')
    payload_width = sum(width for _, width in obj_parts)
    decoder_width = get_operand(image, 0x280fb60, '41b8')
    require(decoder_width == get_operand(image, 0x2883a70, '41b8'), 'decoder widths differ')
    require(payload_width == decoder_width and obj_tag + 1 == obj_parts[0][0], 'object tag/payload mismatch')
    require(tag_input == obj_tag - obj_base and key_input == obj_parts[0][0] - obj_base,
            'object and environment input offsets disagree')
    require(key_input_tail == key_input + 16 and key_staging_tail == key_staging + 16,
            'twenty-byte move has a gap')
    require(key_staging == tag_staging + 1, 'staging tag/payload mismatch')
    require(copy1_src <= tag_staging and key_staging + payload_width <= copy1_src + copy1_len,
            'first bulk copy does not contain destination')
    moved_tag = copy1_dst + tag_staging - copy1_src
    moved_key = copy1_dst + key_staging - copy1_src
    require(copy2_src <= moved_tag and moved_key + payload_width <= copy2_src + copy2_len,
            'second bulk copy does not contain destination')
    env_tag = copy2_dst + moved_tag - copy2_src - env_base
    env_key = copy2_dst + moved_key - copy2_src - env_base
    require(0 <= env_tag < env_key and env_key + payload_width <= env_size,
            'environment field outside allocated object')
    lengths = [get_operand(image, site, 'ba') for site in
               (0x1bdb4ad, 0x1bdb4d3, 0x1b2b02b, 0x1e6902a, 0x1e69071, 0x1f6ebcd,
                0x1f6ed50, 0x27bff3a, 0x27c025f, 0x247df3f)]
    tail_lengths = [get_operand(image, site, 'ba') for site in
                    (0x1bdb53c, 0x1b2b068, 0x1b2b0dd, 0x1b2b0fc, 0x1e68fc2)]
    tail_start = get_operand(image, 0x1bdb537, '498d7c24', 1)
    require(get_operand(image, 0x1b2b0f0, '488d7b', 1) == tail_start,
            'reconstructed object tail offsets differ')
    require(len(set(lengths)) == len(set(tail_lengths)) == 1
            and lengths[0] == tail_start + tail_lengths[0]
            and tail_start <= tag_input and key_input + payload_width <= lengths[0],
            'request copies do not preserve selected fields')
    key_literal = image.read(0x21a0f51 + 3, 2)
    field_code = image.read(0x21a0f5c + 2, 1)[0]
    require(key_literal == b'to' and image.read(0x21a112c + 3, 2) == key_literal,
            'field-name comparator changed')
    require(image.read(0x21a1137 + 2, 1)[0] == field_code, 'field classifiers disagree')
    field_base = image.read(0x1bda5a1 + 2, 1)[0]
    require(image.read(0x1bda59e + 2, 1)[0] == ((-field_base) & 0xff), 'field dispatch bias changed')
    dispatch_index = field_code - field_base
    request_table = [r for r in tables if r['table'] == 'object-fields']
    require(0 <= dispatch_index < len(request_table) and request_table[dispatch_index]['target'] == 0x1bda952,
            'field does not reach the selected guard')
    duplicate_literal = rip_target(image, 0x1bdc4f2, '488d05')
    duplicate_length = get_operand(image, 0x1bdc501, '48c78424d8050000')
    require(duplicate_length == len(key_literal) and image.read(duplicate_literal, duplicate_length) == key_literal,
            'duplicate label differs')
    tag_some = get_operand(image, 0x26a994c, 'b2', 1)
    tag_absent = get_operand(image, 0x1bdb6bc, '41b5', 1)
    null_pair = image.read(0x2523d15 + 3, 2)
    require(null_pair == bytes((0, tag_absent)) and tag_some == 1 and tag_absent == 2,
            'nullable tag representation changed')
    require(get_operand(image, 0x247ef55, 'c7442414') == 0, 'none-to-zero conversion changed')
    auxiliary = []
    for parser, default_cmp, accepted_cmp, error_jump, error_target in [
        (0x1e67fb0, 0x1f6ebf5, 0x1f6ec2f, 0x1f6ec33, 0x1f6f05a),
        (0x1e67a80, 0x1f6ec85, 0x1f6ecb2, 0x1f6ecb6, 0x1f6f0cf),
        (0x1e67d60, 0x1f6ecfc, 0x1f6ed36, 0x1f6ed3a, 0x1f6f163),
    ]:
        default_tag = get_operand(image, default_cmp, '4983fe', 1)
        accepted_low32 = get_operand(image, accepted_cmp, '4183fe', 1)
        branch = checked_edge(image.read(error_jump, 6), error_jump, 'jcc', error_target)
        require(default_tag == 4 and accepted_low32 == 3 and branch['condition'] == 5,
                'auxiliary result branch changed')
        auxiliary.append({'parser_va': hex(parser), 'default_tag': default_tag,
                          'accepted_low32': accepted_low32, 'other_branch_va': hex(error_target)})
    gate_mode_field = get_operand(image, 0x247dba2, '4183b8')
    gate_mode = get_operand(image, 0x247dba2, '4183b880000000', 1)
    gate_word_field = get_operand(image, 0x247dbb6, '4981b8')
    cap = get_operand(image, 0x247dbb6, '4981b888000000')
    early_error_tag = get_operand(image, 0x247dbc3, '41c607', 1)
    early_error_subtype = get_operand(image, 0x247dbc7, '41c64708', 1)
    limit_store_offset = get_operand(image, 0x247dbdc, '49c74424', 1)
    limit_store_value = get_operand(image, 0x247dbdc, '49c7442470')
    zero_block_offset = get_operand(image, 0x247dbe9, 'f3410f7f4424', 1)
    zero_qword_offset = get_operand(image, 0x247dbf0, '49c78424')
    zero_qword_value = get_operand(image, 0x247dbf0, '49c7842488000000')
    state_byte_offsets = [get_operand(image, site, '41c646', 1) for site in (0x247dbfc, 0x247dc01)]
    state_byte_values = [image.read(site + 4, 1)[0] for site in (0x247dbfc, 0x247dc01)]
    input_zero_offset = get_operand(image, 0x247dc06, '49c780')
    input_zero_value = get_operand(image, 0x247dc06, '49c78090000000')
    error_rows = [r for r in tables if r['table'] == 'error-dispatch-prefix']
    require(len(error_rows) > early_error_tag and error_rows[early_error_tag]['target'] == 0x4e5cc7b,
            'preparation error does not reach selected dispatch arm')
    require(rip_target(image, 0x27c072a, 'ff15') == 0x5770930
            and rip_target(image, 0x27c0996, 'ff15') == 0x5770930
            and rip_target(image, 0x27c08a8, 'ff15') == 0x5774eb0
            and rip_target(image, 0x4e5ccc2, 'ff15') == 0x5776e78
            and rip_target(image, 0x4e5da06, 'ff15') == 0x5776e58,
            'result or formatting dispatch slot changed')
    first_copy_dst = get_operand(image, 0x27c051e, '488dbc24')
    first_copy_src = get_operand(image, 0x27c0526, '488db424')
    first_copy_len = get_operand(image, 0x27c052e, 'ba')
    second_copy_dst = get_operand(image, 0x27c0569, '488dbc24')
    second_copy_src = get_operand(image, 0x27c0571, '488db424')
    second_copy_len = get_operand(image, 0x27c0579, 'ba')
    staged_error_tag = get_operand(image, 0x27c03ea, '888424')
    staged_error_payload = get_operand(image, 0x27c03f1, '48898c24')
    staged_marker = get_operand(image, 0x27c0400, '48899c24')
    marker = get_operand(image, 0x27c02db, '48bb', 8)
    require(staged_error_tag == staged_marker + 8 and staged_error_payload == staged_error_tag + 8
            and staged_marker == first_copy_src and first_copy_dst == second_copy_src
            and first_copy_len == second_copy_len and first_copy_len > 16,
            'preparation error staging changed')
    subtype_start = -int.from_bytes(image.read(0x4e5d9a1, 1), 'little', signed=True)
    subtype_count = get_operand(image, 0x4e5d9a2, '83f9', 1)
    other_subtype = get_operand(image, 0x4e5d9b1, '83f8', 1)
    common_code = get_operand(image, 0x4e5d9b6, 'bd')
    signed_code = int.from_bytes(common_code.to_bytes(4, 'little'), 'little', signed=True)
    require(subtype_start <= early_error_subtype < subtype_start + subtype_count
            and signed_code == -32000, 'selected preparation error code changed')
    result_success_tag = get_operand(image, 0x4e591c0, 'c603', 1)
    require(get_operand(image, 0x27c08b6, '3c', 1) == result_success_tag,
            'result success tag differs at caller')
    result_output_tag = get_operand(image, 0x27c08e7, '48c703')
    packed_error_tag = get_operand(image, 0x4e5da30, '48c703')
    packed_error_kind = get_operand(image, 0x4e5da26, 'c74330')
    error_kind_offset = get_operand(image, 0x4e5da26, 'c743', 1)
    error_code_offset = get_operand(image, 0x4e5da2d, '896b', 1)
    rpc_input_base = get_operand(image, 0x1f6edad, '4c8bb424')
    rpc_payload_source = get_operand(image, 0x1f6edd7, 'f30f6f8424') - rpc_input_base
    rpc_wrapper_base = get_operand(image, 0x1f6ee74, '488d9424')
    rpc_tag_offset = get_operand(image, 0x1f6ee14, '4c89b424') - rpc_wrapper_base
    rpc_payload_dst = get_operand(image, 0x1f6ee3b, '0f118424') - rpc_wrapper_base
    wrapper_tag_offset = get_operand(image, 0x24cc127, '41837e', 1)
    wrapper_success_tag = get_operand(image, 0x24cc127, '41837e10', 1)
    wrapper_kind_offset = get_operand(image, 0x24cc1ae, '418b4e', 1)
    wrapper_code_offset = get_operand(image, 0x24cc7a8, '418b4e', 1)
    wrapper_output_flag_offset = get_operand(image, 0x24cc37a, '41895f', 1)
    wrapper_output_code_offset = get_operand(image, 0x24cc382, '418947', 1)
    wrapper_error_kind = get_operand(image, 0x24cc1b2, 'bb')
    rpc_rows = [r for r in tables if r['table'] == 'rpc-error-prefix']
    require(rpc_tag_offset == wrapper_tag_offset and wrapper_success_tag == result_output_tag
            and rpc_payload_dst + error_kind_offset - rpc_payload_source == wrapper_kind_offset
            and rpc_payload_dst + error_code_offset - rpc_payload_source == wrapper_code_offset
            and 0 <= error_kind_offset - rpc_payload_source < 16
            and 0 <= error_code_offset - rpc_payload_source <= 12
            and len(rpc_rows) > packed_error_kind and rpc_rows[packed_error_kind]['target'] == 0x24cc7a8,
            'response wrapper field mapping changed')
    result_bias = get_operand(image, 0x4e59154, '48b9', 8)
    special_variant = get_operand(image, 0x4e5916d, '4883f8', 1)
    result_selector_offset = get_operand(image, 0x4e591a7, '0fb646', 1)
    result_selector_shift = get_operand(image, 0x4e591ab, 'c1e0', 1)
    result_payload_offset = get_operand(image, 0x4e591ae, '0f104406', 1)
    result_payload_tail = get_operand(image, 0x4e591b3, '0f104c06', 1)
    result_aux_offset = get_operand(image, 0x4e591d1, '0fb646', 1)
    small_aux_count = get_operand(image, 0x4e591db, '4883f8', 1)
    small_map = get_operand(image, 0x4e59244, '48bf', 8).to_bytes(8, 'little')[:small_aux_count]
    generic_tag = get_operand(image, 0x4e59251, 'c603', 1)
    special_tag = get_operand(image, 0x4e59213, 'c603', 1)
    special_subtype = get_operand(image, 0x4e59216, 'c64308', 1)
    fallback_subtype = get_operand(image, 0x4e591ec, '40b7', 1)
    auxiliary_subtract = -int.from_bytes(image.read(0x4e591d8, 1), 'little', signed=True)
    auxiliary_threshold = get_operand(image, 0x4e591ef, '4883f9', 1)
    threshold_subtype = get_operand(image, 0x4e591f5, '40b7', 1)
    require(result_bias == 0x8000000000000001 and special_variant == 1
            and result_payload_tail == result_payload_offset + 16 and len(small_map) == 5
            and special_tag == generic_tag and auxiliary_subtract == small_aux_count - 1,
            'result variant instruction shapes changed')
    require(limit_store_value == cap and zero_qword_value == input_zero_value == 0,
            'preparation store values changed')
    descriptor_slot = next(r['slot'] for r in relas if r['slot'] == 0x5691888)
    descriptor = descriptor_slot - 0x18
    require(descriptor + 0x20 == 0x5691890 and descriptor + 0x28 == 0x5691898,
            'descriptor slot spacing changed')
    nine = image.read(0x574f0c0, payload_width)
    require(nine == bytes(payload_width - 1) + b'\x09', 'prior object address changed')
    return {
        'field': {'key_ascii': key_literal.decode('ascii'), 'field_discriminant': field_code,
                  'switch_bias': field_base, 'switch_index': dispatch_index,
                  'field_guard_va': hex(request_table[dispatch_index]['target']),
                  'duplicate_key_literal_va': hex(duplicate_literal)},
        'object': {'copy_size': lengths[0], 'full_copy_sites': len(lengths),
                   'tail_copy_start': tail_start, 'tail_copy_size': tail_lengths[0],
                   'tail_copy_sites': len(tail_lengths), 'tag_offset': tag_input, 'payload_offset': key_input,
                   'payload_size': payload_width, 'some_tag': tag_some, 'absent_or_null_tag': tag_absent,
                   'packed_result_stack_offsets': [hex(offset) for offset, _ in obj_parts],
                   'packed_result_widths': [width for _, width in obj_parts]},
        'environment': {'staging_tag_offset': tag_staging, 'staging_key_offset': key_staging,
                        'copy1': {'source': copy1_src, 'destination': copy1_dst, 'size': copy1_len},
                        'copy2': {'source': copy2_src, 'destination': copy2_dst, 'size': copy2_len},
                        'object_stack_base': env_base, 'allocated_size': env_size,
                        'tag_offset': env_tag, 'payload_offset': env_key},
        'result_variants': {'bias': hex(result_bias), 'special_variant': special_variant,
                            'selector_offset': result_selector_offset, 'selector_shift': result_selector_shift,
                            'payload_offset': result_payload_offset, 'payload_size': 32,
                            'auxiliary_offset': result_aux_offset, 'small_auxiliary_map': list(small_map),
                            'auxiliary_subtract': auxiliary_subtract, 'auxiliary_threshold': auxiliary_threshold,
                            'threshold_subtype': threshold_subtype, 'fallback_subtype': fallback_subtype,
                            'error_tag': generic_tag, 'special_subtype': special_subtype},
        'response': {'prepare_error_dispatch_va': hex(error_rows[early_error_tag]['target']),
                     'error_dispatch_slot': '0x5770930', 'subtype_dispatch_slot': '0x5776e78',
                     'formatter_slot': '0x5776e58', 'result_dispatch_slot': '0x5774eb0',
                     'stage_marker_offset': staged_marker, 'stage_error_tag_offset': staged_error_tag,
                     'stage_error_payload_offset': staged_error_payload, 'error_marker': hex(marker),
                     'first_copy': {'source': first_copy_src, 'destination': first_copy_dst, 'size': first_copy_len},
                     'second_copy': {'source': second_copy_src, 'destination': second_copy_dst, 'size': second_copy_len},
                     'subtype_range_start': subtype_start, 'subtype_range_count': subtype_count,
                     'other_common_code_subtype': other_subtype, 'prepare_limit_error_code': signed_code,
                     'packed_error_tag': packed_error_tag, 'packed_error_kind': packed_error_kind,
                     'packed_error_kind_offset': error_kind_offset, 'packed_error_code_offset': error_code_offset,
                     'wrapper_input_tag_offset': wrapper_tag_offset, 'wrapper_input_kind_offset': wrapper_kind_offset,
                     'wrapper_input_code_offset': wrapper_code_offset, 'wrapper_output_error_flag': wrapper_error_kind,
                     'wrapper_output_flag_offset': wrapper_output_flag_offset,
                     'wrapper_output_code_offset': wrapper_output_code_offset,
                     'wrapper_kind_arm_va': hex(rpc_rows[packed_error_kind]['target']),
                     'result_success_tag': result_success_tag, 'returned_success_tag': result_output_tag},
        'auxiliary_arguments': auxiliary,
        'preparation': {'word_limit': cap, 'check_mode': gate_mode,
                        'early_error_tag': early_error_tag, 'early_error_subtype': early_error_subtype,
                        'mode_field_offset': gate_mode_field, 'word_field_offset': gate_word_field,
                        'limit_store_offset': limit_store_offset, 'limit_store_value': limit_store_value,
                        'zero_block_offset': zero_block_offset, 'zero_block_size': 16,
                        'zero_qword_offset': zero_qword_offset, 'zero_qword_value': zero_qword_value,
                        'state_byte_offsets': state_byte_offsets, 'state_byte_values': state_byte_values,
                        'input_zero_offset': input_zero_offset, 'input_zero_value': input_zero_value},
        'descriptor_candidate': {'vtable_va': hex(descriptor), 'method_relocations': [hex(r['slot']) for r in relas
                          if descriptor + 0x18 <= r['slot'] <= descriptor + 0x28]},
        'target_key_va': hex(0x574f0c0), 'target_key_hex': nine.hex(),
        'limitations': 'Byte-copy composition is conditional on the selected branches, normal helper returns, '
                       'nonaliasing and ordinary memcpy resolution. No code is executed.'
    }


def synthetic_case(flow, kind, payload=None, gate_mode=0, gate_word=0):
    """Model only selected tag/copy predicates, with no instruction or target execution."""
    require(type(gate_mode) is int and 0 <= gate_mode < (1 << 32)
            and type(gate_word) is int and 0 <= gate_word < (1 << 64), 'invalid synthetic gate operand')
    cap = flow['preparation']['word_limit']
    if kind in ('duplicate', 'decode-error'):
        return {'outcome': 'field-error', 'env_tag': None, 'key_hex': None, 'matches_nine': False, 'conditional_error_code': None}
    if gate_mode == flow['preparation']['check_mode'] and gate_word > cap:
        return {'outcome': 'early-limit-error', 'env_tag': None, 'key_hex': None, 'matches_nine': False,
                'conditional_error_code': flow['response']['prepare_limit_error_code']}
    obj = bytearray(flow['object']['copy_size'])
    tag_pos, key_pos = flow['object']['tag_offset'], flow['object']['payload_offset']
    if kind in ('null', 'absent'):
        obj[tag_pos] = flow['object']['absent_or_null_tag']
        return {'outcome': 'address-absent', 'env_tag': 0, 'key_hex': None, 'matches_nine': False, 'conditional_error_code': None}
    require(kind == 'some' and isinstance(payload, bytes) and len(payload) == flow['object']['payload_size'],
            'invalid synthetic payload')
    obj[tag_pos] = flow['object']['some_tag']
    obj[key_pos:key_pos + len(payload)] = payload
    staged = bytearray(flow['environment']['copy1']['source'] + flow['environment']['copy1']['size'])
    start = flow['environment']['staging_tag_offset']
    staged[start:start + 1 + len(payload)] = obj[tag_pos:tag_pos + 1 + len(payload)]
    c1, c2 = flow['environment']['copy1'], flow['environment']['copy2']
    first = bytearray(max(c1['destination'] + c1['size'], c2['source'] + c2['size']))
    first[c1['destination']:c1['destination'] + c1['size']] = staged[c1['source']:c1['source'] + c1['size']]
    second = bytearray(c2['destination'] + c2['size'])
    second[c2['destination']:c2['destination'] + c2['size']] = first[c2['source']:c2['source'] + c2['size']]
    env = second[flow['environment']['object_stack_base']:]
    tag = env[flow['environment']['tag_offset']]
    off = flow['environment']['payload_offset']
    key = bytes(env[off:off + len(payload)])
    return {'outcome': 'address-preserved' if tag == 1 else 'address-absent', 'env_tag': tag,
            'key_hex': key.hex(), 'matches_nine': key.hex() == flow['target_key_hex'],
            'conditional_error_code': None}


def result_variant_case(flow, record):
    """Model only the pinned return-variant tests and byte selection, not cleanup."""
    spec = flow['result_variants']
    require(isinstance(record, bytes) and len(record) >= 8, 'short result record')
    word = int.from_bytes(record[:8], 'little')
    marker = ((word + int(spec['bias'], 16)) & ((1 << 64) - 1)) if word >> 63 else 0
    if marker == 0:
        require(len(record) > spec['selector_offset'], 'missing result selector')
        start = spec['payload_offset'] + (record[spec['selector_offset']] << spec['selector_shift'])
        end = start + spec['payload_size']
        require(end <= len(record), 'result payload out of range')
        return {'kind': 'payload', 'tag': flow['response']['result_success_tag'],
                'subtype': None, 'payload_start': start, 'payload_hex': record[start:end].hex()}
    if marker == spec['special_variant']:
        return {'kind': 'special-error', 'tag': spec['error_tag'],
                'subtype': spec['special_subtype'], 'payload_start': None, 'payload_hex': ''}
    require(len(record) > spec['auxiliary_offset'], 'missing result auxiliary byte')
    aux = record[spec['auxiliary_offset']]
    if aux < len(spec['small_auxiliary_map']):
        subtype = spec['small_auxiliary_map'][aux]
    elif aux - spec['auxiliary_subtract'] == spec['auxiliary_threshold']:
        subtype = spec['threshold_subtype']
    else:
        subtype = spec['fallback_subtype']
    return {'kind': 'generic-error', 'tag': spec['error_tag'], 'subtype': subtype,
            'payload_start': None, 'payload_hex': ''}


def render_tsv(rows, columns):
    import io
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[column] for column in columns])
    return output.getvalue().encode('utf-8')


def encode_json(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def collect(data, *, authenticate=True):
    if authenticate:
        check_digest(data)
    secs, index = unwind_index(data)
    image = Image(data, secs)
    cies, frames = eh_frame_records(data, secs)
    by_start = {}
    for frame in frames:
        by_start.setdefault(frame['start'], []).append(frame)
    indexed = {row['start']: row['fde'] for row in index}
    function_rows, raw_functions, unwind_rows = [], [], []
    for start, expected_end, expected_hash in FUNCTIONS:
        candidates = by_start.get(start, [])
        require(len(candidates) == 1, 'selected FDE missing or duplicated')
        frame = candidates[0]
        require(frame['end'] == expected_end and indexed.get(start) == frame['fde'],
                'selected FDE extent or index changed')
        body = image.read(start, frame['end'] - start)
        window_ok(body, expected_hash)
        raw_functions.append({'start_va': hex(start), 'end_va': hex(frame['end']), 'bytes': body.hex()})
        function_rows.append({'start_va': hex(start), 'end_va': hex(frame['end']),
                              'size': len(body), 'file_offset': hex(image.offset(start, len(body))),
                              'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie']),
                              'lsda_va': '' if frame['lsda'] is None else hex(frame['lsda']),
                              'sha256': hashlib.sha256(body).hexdigest(), 'role': ROLES[start]})
        fde_head = image.read(frame['fde'], 4)
        fde_size = 4 + struct.unpack('<I', fde_head)[0]
        cie_head = image.read(frame['cie'], 4)
        cie_size = 4 + struct.unpack('<I', cie_head)[0]
        require(frame['cie'] in cies and fde_size >= 8 and cie_size >= 8, 'invalid unwind record')
        unwind_rows.append({'start_va': hex(start), 'fde_va': hex(frame['fde']),
                            'fde_bytes': image.read(frame['fde'], fde_size).hex(),
                            'cie_va': hex(frame['cie']), 'cie_bytes': image.read(frame['cie'], cie_size).hex(),
                            'lsda_va': None if frame['lsda'] is None else hex(frame['lsda'])})
    window_rows = []
    for name, start, end, expected in WINDOWS:
        raw = image.read(start, end - start)
        window_ok(raw, expected)
        if name not in BOUNDARY_WINDOWS:
            require(any(a <= start and end <= b for a, b, _ in FUNCTIONS), 'window outside selected FDE')
        window_rows.append({'name': name, 'ownership': 'dependency' if name in BOUNDARY_WINDOWS else 'selected',
                            'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(image.offset(start, len(raw))),
                            'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()})
    edges = []
    for site, kind, expected_target in EDGES:
        row = checked_edge(image.read(site, 6), site, kind, expected_target)
        edges.append({'site_va': hex(site), 'kind': row['kind'],
                      'condition_nibble': '' if row['condition'] == '' else hex(row['condition']),
                      'target_va': hex(row['target']), 'fallthrough_va': hex(row['fallthrough']), 'bytes': row['bytes']})
    base_borrowed = rip_target(image, 0x21a0f41, '488d3d')
    base_owned = rip_target(image, 0x21a111c, '488d0d')
    base_object = rip_target(image, 0x1bda5bb, '488d35')
    length_count = image.read(0x21a0f37 + 3, 1)[0] + 1
    require(image.read(0x21a1112 + 3, 1)[0] + 1 == length_count, 'classifier table sizes differ')
    field_count = get_operand(image, 0x1bda5a7, 'be') + 1
    tables = (table_rows(image, 'borrowed-lengths', base_borrowed, length_count, (0x21a0f30, 0x21a10fe))
              + table_rows(image, 'owned-lengths', base_owned, length_count, (0x21a1100, 0x21a135a))
              + table_rows(image, 'object-fields', base_object, field_count, (0x1bda270, 0x1bdce65))
              + table_rows(image, 'error-dispatch-prefix', rip_target(image, 0x4e5c72a, '488d0d'),
                           get_operand(image, 0x247dbc3, '41c607', 1) + 1, (0x4e5c710, 0x4e5d582))
              + table_rows(image, 'rpc-error-prefix', rip_target(image, 0x24cc1b7, '488d15'),
                           get_operand(image, 0x4e5da26, 'c74330') + 1, (0x24cc0c0, 0x24cca98)))
    require(tables[0]['target'] == 0x21a0f51 and tables[length_count]['target'] == 0x21a112c,
            'length-two entry changed')
    relas = relocations(data, secs)
    flow = derive_flow(image, tables, relas)
    flow['target_key_file_offset'] = hex(image.offset(int(flow['target_key_va'], 16), flow['object']['payload_size']))
    nine = bytes.fromhex(flow['target_key_hex'])
    cases = []
    for name, kind, value, mode, word in [
        ('present-nine', 'some', nine, 0, 0),
        ('present-neighbor', 'some', nine[:-1] + b'\x08', 0, 0),
        ('explicit-null', 'null', None, 0, 0),
        ('absent-field', 'absent', None, 0, 0),
        ('duplicate-field', 'duplicate', None, 0, 0),
        ('decoder-error', 'decode-error', None, 0, 0),
        ('limit-equal', 'some', nine, 1, flow['preparation']['word_limit']),
        ('limit-plus-one', 'some', nine, 1, flow['preparation']['word_limit'] + 1),
        ('other-mode-plus-one', 'some', nine, 0, flow['preparation']['word_limit'] + 1),
    ]:
        result = synthetic_case(flow, kind, value, mode, word)
        cases.append({'name': name, 'kind': kind, 'gate_mode': mode, 'gate_word': word,
                      'payload_hex': '' if value is None else value.hex(), 'outcome': result['outcome'],
                      'env_tag': '' if result['env_tag'] is None else result['env_tag'],
                      'key_hex': result['key_hex'] or '', 'matches_nine': str(result['matches_nine']).lower(),
                      'conditional_error_code': '' if result['conditional_error_code'] is None else result['conditional_error_code']})
    variant_cases = []
    for name, word, selector, aux in [
        ('payload-first', 0, 0, 0), ('payload-next', 0, 1, 0),
        ('special-variant', 1 << 63, 0, 0),
        *[('generic-' + str(aux), (1 << 63) + 1, 0, aux) for aux in (0, 1, 2, 3, 4, 5, 13, 14, 15, 255)],
    ]:
        record = bytearray(range(128))
        record[:8] = word.to_bytes(8, 'little')
        record[flow['result_variants']['selector_offset']] = selector
        record[flow['result_variants']['auxiliary_offset']] = aux
        result = result_variant_case(flow, bytes(record))
        variant_cases.append({'name': name, 'header_hex': hex(word), 'selector': selector, 'auxiliary_byte': aux,
                              'kind': result['kind'], 'tag': result['tag'],
                              'subtype': '' if result['subtype'] is None else result['subtype'],
                              'payload_start': '' if result['payload_start'] is None else result['payload_start'],
                              'payload_hex': result['payload_hex']})
    summary = {'binary_sha256': TARGET_SHA256, 'selected_fde_count': len(function_rows),
               'selected_fde_bytes': sum(row['size'] for row in function_rows),
               'selected_window_count': sum(row['ownership'] == 'selected' for row in window_rows),
               'dependency_window_count': sum(row['ownership'] == 'dependency' for row in window_rows),
               'selected_control_count': len(edges), 'relative_table_entries': len(tables),
               'relocation_records': len(relas), 'synthetic_cases': len(cases), 'result_variant_cases': len(variant_cases),
               'limitations': 'These are selected evidence counts, not coverage or equivalence. '
                              'CIE/FDE extents describe unwind ranges. External helpers, dynamically installed '
                              'callbacks and the previously mapped registry, frame and wrapper remain dependencies.'}
    table_output = [{'table': r['table'], 'index': r['index'], 'slot_va': hex(r['slot']),
                     'raw': r['raw'], 'target_va': hex(r['target'])} for r in tables]
    reloc_output = [{'slot_va': hex(r['slot']), 'type': r['type'], 'symbol_index': r['symbol_index'],
                     'symbol': r['symbol'], 'addend': hex(r['addend']), 'file_offset': hex(r['file_offset']),
                     'raw': r['raw'], 'symbol_file_offset': '' if r['symbol_file_offset'] is None else hex(r['symbol_file_offset']),
                     'symbol_raw': r['symbol_raw'], 'name_bytes': r['name_bytes']} for r in relas]
    return {
        'functions.tsv': render_tsv(function_rows, ['start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'role']),
        'windows.tsv': render_tsv(window_rows, ['name', 'ownership', 'start_va', 'end_va', 'file_offset', 'bytes', 'sha256']),
        'control.tsv': render_tsv(edges, ['site_va', 'kind', 'condition_nibble', 'target_va', 'fallthrough_va', 'bytes']),
        'switch-tables.tsv': render_tsv(table_output, ['table', 'index', 'slot_va', 'raw', 'target_va']),
        'relocations.tsv': render_tsv(reloc_output, ['slot_va', 'type', 'symbol_index', 'symbol', 'addend', 'file_offset', 'raw', 'symbol_file_offset', 'symbol_raw', 'name_bytes']),
        'synthetic-cases.tsv': render_tsv(cases, ['name', 'kind', 'gate_mode', 'gate_word', 'payload_hex', 'outcome', 'env_tag', 'key_hex', 'matches_nine', 'conditional_error_code']),
        'result-variant-cases.tsv': render_tsv(variant_cases, ['name', 'header_hex', 'selector', 'auxiliary_byte', 'kind', 'tag', 'subtype', 'payload_start', 'payload_hex']),
        'function-bytes.json': encode_json(raw_functions),
        'unwind-records.json': encode_json(unwind_rows),
        'flow.json': encode_json(flow),
        'summary.json': encode_json(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in result.items():
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('eth_call_target94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
