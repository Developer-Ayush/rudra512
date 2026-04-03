{
  "targets": [
    {
      "target_name": "rudra512",
      "sources": [
        "rudra.cpp",
        "../../core/src/rudra512.cpp"
      ],
      "include_dirs": [
        "../../core/include",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags_cc": ["-std=c++17"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
    }
  ]
}
