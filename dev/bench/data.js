window.BENCHMARK_DATA = {
  "lastUpdate": 1792402466910,
  "repoUrl": "https://github.com/JamoBox/pktbaffle",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "2273100+JamoBox@users.noreply.github.com",
            "name": "Pete Wicken",
            "username": "JamoBox"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "766aaa4031904c3461ed18f26a6fe8bb300ebd68",
          "message": "Merge pull request #126 from JamoBox/chore/pkttap-0.4.0-release\n\nchore(pkttap): bump to 0.4.0 for release",
          "timestamp": "2026-10-02T21:49:04+01:00",
          "tree_id": "6d99561cbce11b7727261897322c26af1458b724",
          "url": "https://github.com/JamoBox/pktbaffle/commit/766aaa4031904c3461ed18f26a6fe8bb300ebd68"
        },
        "date": 1790974456207,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 112,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 258,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 1092,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1108,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 487,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1124,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3174,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2792,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 419,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2162,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2383,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 15858,
            "range": "± 272",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 144303,
            "range": "± 1200",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 159698,
            "range": "± 2195",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 156243,
            "range": "± 620",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 6312305,
            "range": "± 31334",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "2273100+JamoBox@users.noreply.github.com",
            "name": "Pete Wicken",
            "username": "JamoBox"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "33874fee333392b46e14cb46a2d06bd875b8bfd0",
          "message": "Merge pull request #127 from JamoBox/ccr-91014308-llf3hn\n\nfeat(pkttap): support non-blocking live capture on Windows",
          "timestamp": "2026-10-05T00:09:16+01:00",
          "tree_id": "2717535a5a6e5e84db61bcc9328f5251b9875a68",
          "url": "https://github.com/JamoBox/pktbaffle/commit/33874fee333392b46e14cb46a2d06bd875b8bfd0"
        },
        "date": 1791155633130,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 65,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 151,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 689,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 806,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 312,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 692,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 2108,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 1870,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 253,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 1461,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 1657,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 12086,
            "range": "± 108",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 295649,
            "range": "± 9354",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 305004,
            "range": "± 711",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 300144,
            "range": "± 2535",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 1741818,
            "range": "± 38106",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Pete Wicken",
            "username": "JamoBox",
            "email": "2273100+JamoBox@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "33874fee333392b46e14cb46a2d06bd875b8bfd0",
          "message": "Merge pull request #127 from JamoBox/ccr-91014308-llf3hn\n\nfeat(pkttap): support non-blocking live capture on Windows",
          "timestamp": "2026-10-04T23:09:16Z",
          "url": "https://github.com/JamoBox/pktbaffle/commit/33874fee333392b46e14cb46a2d06bd875b8bfd0"
        },
        "date": 1791198493212,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 102,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 257,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 1144,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1250,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 453,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1079,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3109,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2680,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 421,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2165,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2413,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 50,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 19633,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 185056,
            "range": "± 836",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 198259,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 193146,
            "range": "± 1140",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 5383316,
            "range": "± 76587",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Pete Wicken",
            "username": "JamoBox",
            "email": "2273100+JamoBox@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "33874fee333392b46e14cb46a2d06bd875b8bfd0",
          "message": "Merge pull request #127 from JamoBox/ccr-91014308-llf3hn\n\nfeat(pkttap): support non-blocking live capture on Windows",
          "timestamp": "2026-10-04T23:09:16Z",
          "url": "https://github.com/JamoBox/pktbaffle/commit/33874fee333392b46e14cb46a2d06bd875b8bfd0"
        },
        "date": 1791804983415,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 101,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 268,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 1161,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1235,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 450,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1042,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3006,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2676,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 381,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2072,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2420,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 50,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 19624,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 182695,
            "range": "± 1502",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 197194,
            "range": "± 1005",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 192586,
            "range": "± 1231",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 5308757,
            "range": "± 32596",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "2273100+JamoBox@users.noreply.github.com",
            "name": "Pete Wicken",
            "username": "JamoBox"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a451e5fbc8b311ec4ec6a549bf78097fd8b8943c",
          "message": "Merge pull request #225 from JamoBox/audit/libpcap-parity-220\n\nBatch 0: libpcap-parity audit foundations (#128, #129, #134, #135, #219)",
          "timestamp": "2026-10-12T22:11:42+01:00",
          "tree_id": "e298fd66f779404199ca7e769a6e97ba835a0533",
          "url": "https://github.com/JamoBox/pktbaffle/commit/a451e5fbc8b311ec4ec6a549bf78097fd8b8943c"
        },
        "date": 1791839804187,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 87,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 230,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 1091,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1195,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 430,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1044,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3089,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2773,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 369,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2109,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2396,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 27,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 18986,
            "range": "± 474",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 157189,
            "range": "± 401",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 171598,
            "range": "± 497",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 167823,
            "range": "± 523",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 5311154,
            "range": "± 13509",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "2273100+JamoBox@users.noreply.github.com",
            "name": "Pete Wicken",
            "username": "JamoBox"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5a36d4b06b337b8dc0201585f30c7af5d2d39fba",
          "message": "Merge pull request #231 from JamoBox/batch/1-chain-limits\n\nBatch 1: chain and recursion limits (#149, #199, #202, #229)",
          "timestamp": "2026-10-12T22:27:12+01:00",
          "tree_id": "10c096ba01ee46ec1be836f459d84a0de0beff14",
          "url": "https://github.com/JamoBox/pktbaffle/commit/5a36d4b06b337b8dc0201585f30c7af5d2d39fba"
        },
        "date": 1791840726029,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 181,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 840,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1016,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 473,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 898,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 2892,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2623,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 324,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 1793,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2291,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 11549,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 115790,
            "range": "± 253",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 133451,
            "range": "± 2438",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 135798,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 4925778,
            "range": "± 8590",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Pete Wicken",
            "username": "JamoBox",
            "email": "2273100+JamoBox@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "5a36d4b06b337b8dc0201585f30c7af5d2d39fba",
          "message": "Merge pull request #231 from JamoBox/batch/1-chain-limits\n\nBatch 1: chain and recursion limits (#149, #199, #202, #229)",
          "timestamp": "2026-10-12T21:27:12Z",
          "url": "https://github.com/JamoBox/pktbaffle/commit/5a36d4b06b337b8dc0201585f30c7af5d2d39fba"
        },
        "date": 1792402466082,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 85,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 230,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 1104,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1317,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 524,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1117,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3421,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 3201,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 396,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2286,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2895,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/reject",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/accept",
            "value": 46,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 20,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 16810,
            "range": "± 500",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 158269,
            "range": "± 1142",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 172364,
            "range": "± 3102",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 167810,
            "range": "± 1747",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 5443338,
            "range": "± 227162",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}