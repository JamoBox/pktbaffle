window.BENCHMARK_DATA = {
  "lastUpdate": 1786339456595,
  "repoUrl": "https://github.com/JamoBox/pktbaffle",
  "entries": {
    "Benchmark": [
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
          "id": "0955c356253bb7fb3709ef1ccf89a49e679e081c",
          "message": "Merge pull request #122 from JamoBox/claude/main-branch-failure-vz7u2d\n\nci(bench): bootstrap gh-pages branch so Benchmarks workflow stops failing",
          "timestamp": "2026-08-05T18:36:33Z",
          "url": "https://github.com/JamoBox/pktbaffle/commit/0955c356253bb7fb3709ef1ccf89a49e679e081c"
        },
        "date": 1786339455698,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 94,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 195,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 906,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1008,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 407,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 884,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 2748,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2393,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 331,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 1901,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2174,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "filter/simple/accept",
            "value": 16,
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
            "value": 40,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 15721,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "packet/construction",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/to_owned",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "packet/as_ref_fields",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/unfiltered",
            "value": 300127,
            "range": "± 5570",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 312667,
            "range": "± 8652",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 302615,
            "range": "± 8183",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 2252457,
            "range": "± 39471",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}