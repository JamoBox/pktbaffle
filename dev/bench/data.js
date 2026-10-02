window.BENCHMARK_DATA = {
  "lastUpdate": 1790974456689,
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
      }
    ]
  }
}