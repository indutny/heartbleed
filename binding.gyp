{
  "targets": [{
    "target_name": "heartbleed",
    "include_dirs": [
      "src",
      "<(node_root_dir)/deps/openssl/openssl/include",
    ],
    "sources": [
      "src/heartbleed.cc",
    ],
  }],
}
