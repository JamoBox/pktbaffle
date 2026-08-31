window.BENCHMARK_DATA = {
  "lastUpdate": 1788171908225,
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
          "id": "0955c356253bb7fb3709ef1ccf89a49e679e081c",
          "message": "Merge pull request #122 from JamoBox/claude/main-branch-failure-vz7u2d\n\nci(bench): bootstrap gh-pages branch so Benchmarks workflow stops failing",
          "timestamp": "2026-08-05T18:36:33Z",
          "url": "https://github.com/JamoBox/pktbaffle/commit/0955c356253bb7fb3709ef1ccf89a49e679e081c"
        },
        "date": 1787546565477,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 119,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 237,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 993,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1086,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 482,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1031,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3123,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2794,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 408,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2054,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2421,
            "range": "± 8",
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
            "value": 15,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 17285,
            "range": "± 160",
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
            "value": 140952,
            "range": "± 3350",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 155263,
            "range": "± 456",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 155262,
            "range": "± 1891",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 6348193,
            "range": "± 24067",
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
          "id": "0955c356253bb7fb3709ef1ccf89a49e679e081c",
          "message": "Merge pull request #122 from JamoBox/claude/main-branch-failure-vz7u2d\n\nci(bench): bootstrap gh-pages branch so Benchmarks workflow stops failing",
          "timestamp": "2026-08-05T18:36:33Z",
          "url": "https://github.com/JamoBox/pktbaffle/commit/0955c356253bb7fb3709ef1ccf89a49e679e081c"
        },
        "date": 1788171907283,
        "tool": "cargo",
        "benches": [
          {
            "name": "parse/simple",
            "value": 110,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "parse/medium",
            "value": 249,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "parse/complex",
            "value": 1091,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "parse/boolean_chain",
            "value": 1180,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/simple",
            "value": 473,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/medium",
            "value": 1085,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/complex",
            "value": 3121,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "cbpf/boolean_chain",
            "value": 2708,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/simple",
            "value": 388,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/complex",
            "value": 2124,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "ebpf/boolean_chain",
            "value": 2412,
            "range": "± 15",
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
            "value": 53,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "filter/complex/reject",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/mixed_1000",
            "value": 19640,
            "range": "± 98",
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
            "value": 154580,
            "range": "± 3866",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_match_all",
            "value": 193206,
            "range": "± 7637",
            "unit": "ns/iter"
          },
          {
            "name": "file_capture/filter_reject_all",
            "value": 192228,
            "range": "± 4634",
            "unit": "ns/iter"
          },
          {
            "name": "dump_write/throughput",
            "value": 5415092,
            "range": "± 67804",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}