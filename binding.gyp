{
  "targets": [
    {
      "target_name": "NodeSSPI",
      "sources": [
        "src/*.h",
        "src/*.cpp",
      ],
      'configurations': {
        'Release': {
          'msvs_settings': {
            'VCCLCompilerTool': {
              'ExceptionHandling': 1,
            }
          }
        }
      },
      "include_dirs" : [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}