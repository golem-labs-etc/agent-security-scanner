# Raw model replies

Fixtures for the reply parser, captured from real runs rather than written by
hand. The parser's job is to cope with what a model actually sends, and three
runs were lost to a guess about that: the first version called `JSON.parse` on
the whole reply, and every real reply arrived wrapped in a markdown fence.

To capture one:

    GLANCE_AI_RAW=$PWD/tests/fixtures/interpreter/raw-replies/capture.txt \
      node dist/cli.js analyze --path <dir> --ai

Then trim it to a single reply and commit it with the provider and model in the
filename.

**Check before committing.** A reply can quote the scanned code, so a capture
from a private tree may carry a snippet of it. Capture from a fixture or a
public repository, and read the file before it goes in.

`constructed-*.txt` files are NOT captures. They are shapes written to cover a
case no capture has produced yet, and they say so in their first line.
