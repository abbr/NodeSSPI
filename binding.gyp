{
  "targets": [
    {
      "target_name": "NodeSSPI",
      "sources": [
        "src/*.h",
        "src/*.cpp",
      ],
      "include_dirs" : [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
