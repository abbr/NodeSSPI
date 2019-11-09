{
  "targets": [
    {
      "target_name": "NodeSSPI",
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 }
      },
      "sources": ["src/*.h", "src/*.cpp"],
      "defines": ["_UNICODE", "UNICODE"],
      "configurations": {
        "Release": {
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1
            }
          }
        }
      },
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
    }
  ]
}
