# DS Crawler

This Python tool made to crawl web servers for unintended files/folders  via parser for Apple's `.DS_Store` file format. 

# Usage

```
$ python DS_Crawler.py -h

   /   \/ _\   / __\ __ __ ___      _| | ___ _ __ 
  / /\ /\ \   / / | '__/ _` \ \ /\ / / |/ _ \ '__|
 / /_// _\ \ / /__| | | (_| |\ V  V /| |  __/ |   
/___,'  \__/ \____/_|  \__,_| \_/\_/ |_|\___|_|   
                        v1.0 [0xdeadbeef]
usage: DS_Crawler.py [-h] -u URL [-v]

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  web site that you want to crawl
  -v, --verbose      To enable verbosity

```

# Useful ressources

I found the following links to be quite helpful while developing the parser:

- https://wiki.mozilla.org/DS_Store_File_Format
- http://search.cpan.org/~wiml/Mac-Finder-DSStore/DSStoreFormat.pod
- https://digi.ninja/projects/fdb.php

# License

MIT - See License.md
