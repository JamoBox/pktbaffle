window.BENCHMARK_DATA = {
  "lastUpdate": 1791198493594,
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
      }
    ]
  }
}