// Copy to `ingest_token.local.h` (this file is ignored by git) and set your real token.
//
// You can also define this via PlatformIO build flags:
//   build_flags = -DHTTP_INGEST_TOKEN=\"your_token_here\"
//
// The server expects this token in the JSON body as `ingest_token`.
#pragma once

#define HTTP_INGEST_TOKEN "REPLACE_ME"

