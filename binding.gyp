{
  "targets": [
    {
      "target_name": "NodeSSPI",
      "sources": [
        "src/*.h",
        "src/*.cpp",
      ],
      'defines': [
        '_UNICODE',
        'UNICODE',
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